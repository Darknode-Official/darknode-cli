#!/usr/bin/env python3
# Nexus engine sandbox launcher (Linux Landlock, unprivileged, no setuid).
#
#   python3 -I landlock.py --probe          -> prints the Landlock ABI, exit 0 (or exit 3 + reason)
#   NEXUS_LL_POLICY='{"rw":[...],"ro":[...],"deny":[...]}' python3 -I landlock.py -- <cmd> [args...]
#
# Landlock is allow-list only: the child may read/execute paths under "ro", may also
# write under "rw", and nothing else. "deny" lists paths that must stay unreadable even
# though an ancestor is granted: a granted directory that contains a denied path is not
# granted as a whole; its other entries are granted one by one instead (the directory
# itself gets list-only access). Network access is not restricted.
# The policy is restricted onto this process, then it execs the command, so the engine
# and everything it spawns inherit it. Pure stdlib (ctypes); nothing is installed.
import ctypes, ctypes.util, json, os, struct, sys

SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446  # same numbers on every architecture
CREATE_VERSION = 1
RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38
O_PATH = 0o10000000
O_CLOEXEC = 0o2000000

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR = 1 << 4, 1 << 5, 1 << 6, 1 << 7
MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM = 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12
REFER, TRUNCATE = 1 << 13, 1 << 14
FILE_ONLY = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE

libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.restype = ctypes.c_int


def die(msg, code=3):
    sys.stderr.write("nexus-sandbox: " + msg + "\n")
    sys.exit(code)


def abi():
    v = libc.syscall(SYS_CREATE, None, ctypes.c_size_t(0), ctypes.c_uint32(CREATE_VERSION))
    return v if v > 0 else 0


def handled_for(level):
    h = (EXECUTE | WRITE_FILE | READ_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR | MAKE_DIR
         | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM)
    if level >= 2:
        h |= REFER
    if level >= 3:
        h |= TRUNCATE
    return h


def norm(p):
    return os.path.normpath(os.path.abspath(os.path.expanduser(p)))


def under(child, parent):
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--probe":
        if not sys.platform.startswith("linux"):
            die("not Linux")
        level = abi()
        if not level:
            die("Landlock is not enabled in this kernel")
        print(level)
        return
    try:
        sep = sys.argv.index("--")
    except ValueError:
        die("usage: landlock.py -- <command> [args...]", 2)
    cmd = sys.argv[sep + 1:]
    if not cmd:
        die("no command given", 2)
    try:
        pol = json.loads(os.environ.pop("NEXUS_LL_POLICY", "") or "{}")
    except ValueError:
        die("bad NEXUS_LL_POLICY", 2)

    level = abi()
    if not level:
        die("Landlock is not enabled in this kernel")
    handled = handled_for(level)
    read = EXECUTE | READ_FILE | READ_DIR
    write = handled

    attr = struct.pack("=Q", handled)  # only handled_access_fs: valid for every ABI
    fd = libc.syscall(SYS_CREATE, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if fd < 0:
        die("landlock_create_ruleset failed (errno %d)" % ctypes.get_errno())

    deny = set()
    for p in pol.get("deny") or []:
        deny.add(norm(p))
        deny.add(os.path.realpath(norm(p)))  # a symlinked ~/.ssh is denied at its target too
    added = {}
    split = set()

    def add(path, access):
        try:
            pfd = os.open(path, O_PATH | O_CLOEXEC)
        except OSError:
            return  # missing paths are simply not granted
        try:
            if not os.path.isdir(path):
                access &= FILE_ONLY
            access &= handled
            if not access:
                return
            buf = ctypes.create_string_buffer(struct.pack("=Qi", access, pfd), 12)
            if libc.syscall(SYS_ADD, ctypes.c_int(fd), ctypes.c_int(RULE_PATH_BENEATH), buf, ctypes.c_uint32(0)) != 0:
                die("landlock_add_rule failed for %s (errno %d)" % (path, ctypes.get_errno()))
            added[path] = added.get(path, 0) | access
        finally:
            os.close(pfd)

    def grant(path, access, depth=0):
        if path in deny:
            return
        real = os.path.realpath(path)  # rules bind to inodes: judge the target, so a link to / or $HOME can't widen the grant
        if real in deny:
            return
        inside = [d for d in deny if under(d, real) and d != real]
        if not inside:
            add(real, access)
            return
        if depth > 12 or not os.path.isdir(real) or (real, access) in split:
            return
        split.add((real, access))
        add(real, READ_DIR)  # list the directory, but grant its entries one by one
        try:
            names = os.listdir(real)
        except OSError:
            return
        for n in names:
            grant(os.path.join(real, n), access, depth + 1)

    for p in pol.get("ro") or []:
        grant(norm(p), read)
    for p in pol.get("rw") or []:
        grant(norm(p), write)

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        die("prctl(NO_NEW_PRIVS) failed (errno %d)" % ctypes.get_errno())
    if libc.syscall(SYS_RESTRICT, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
        die("landlock_restrict_self failed (errno %d)" % ctypes.get_errno())
    os.close(fd)
    os.environ["NEXUS_SANDBOXED"] = "landlock-%d" % level
    try:
        os.execvp(cmd[0], cmd)
    except OSError as e:
        die("cannot run %s: %s" % (cmd[0], e.strerror), 127)


if __name__ == "__main__":
    main()
