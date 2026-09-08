"use strict";
// ================= CTF helper — Capture The Flag challenge solver assistance =================
// Knowledge base + heuristics to help a player triage an unknown challenge fast:
//   - CTF_CATEGORIES:        the 7 classic categories, each with techniques/tools/tips
//   - COMMON_FLAG_FORMATS:   regexes for recognizing a flag once you see one
//   - CIPHER_IDENTIFIERS:    pattern-matching detectors for 20+ classic/CTF-favorite ciphers
//   - STEGANOGRAPHY_CHECKS:  the standard stego toolbox (file type -> tool -> command)
//   - identifyChallenge():   scores a free-text challenge description against the categories
//   - suggestApproach():     turns a category + clues into a concrete step-by-step plan
// Node.js built-ins only (crypto for basic base64/hex sanity checks). No network calls,
// no execution of untrusted challenge files — this module only ADVISES, it never runs
// arbitrary binaries or downloads on the user's behalf.

const crypto = require("crypto");

// ---------------------------------------------------------------------------------------
// CTF_CATEGORIES — the 7 classic categories and how to approach them
// ---------------------------------------------------------------------------------------
const CTF_CATEGORIES = {
  web: {
    description:
      "Web exploitation challenges target a live web application: broken auth, injection " +
      "flaws, logic bugs, misconfigurations, or exposed source. The flag usually sits behind " +
      "an access-control bypass or a server-side vulnerability.",
    commonChallenges: [
      "Login bypass / broken authentication",
      "SQL injection to dump a flags table",
      "Server-Side Template Injection (SSTI)",
      "Server-Side Request Forgery (SSRF) to hit an internal metadata endpoint",
      "Insecure Direct Object Reference (IDOR) to read another user's data",
      "Local/Remote File Inclusion (LFI/RFI)",
      "Cross-Site Scripting (XSS) to steal an admin cookie or bot session",
      "XML External Entity (XXE) injection",
      "Insecure deserialization (PHP objects, Python pickle, Java gadgets)",
      "JWT forgery (alg:none, weak secret, kid injection)",
      "Command injection via a form field or upload filename",
      "Prototype pollution in a Node.js backend",
      "Race conditions on a purchase/redeem endpoint",
      "GraphQL introspection abuse",
      "Exposed .git directory or backup files leaking source",
    ],
    techniques: [
      "View page source and all linked JS/CSS for comments, hidden endpoints, API keys",
      "Check robots.txt, sitemap.xml, /.well-known/, and common backup extensions (.bak, ~, .swp)",
      "Fuzz directories and files with a wordlist (ffuf/gobuster) before guessing manually",
      "Inspect every HTTP response header, especially Set-Cookie, Server, and custom X- headers",
      "Try default/weak credentials (admin:admin, test:test) and SQLi auth bypass payloads",
      "Fingerprint the framework (error pages, cookie names, Server header) to pick payloads",
      "Diff behavior between valid and invalid input to find injection points (error-based)",
      "For SSTI, probe with {{7*7}}, ${7*7}, #{7*7} and watch which one evaluates",
      "For IDOR, increment/decrement numeric IDs or swap UUIDs between two throwaway accounts",
      "Decode and re-sign JWTs; try alg:none, blank secret, and the challenge name as HS256 key",
      "Check for a Content-Security-Policy bypass gadget when building an XSS payload",
      "Pull the .git directory with git-dumper if exposed, then inspect the full history",
      "Look for a debug/admin panel left enabled (e.g. /phpinfo.php, /actuator, /debug)",
      "Test file upload filters with double extensions, null bytes, and content-type spoofing",
    ],
    tools: [
      "Burp Suite / OWASP ZAP (intercepting proxy)",
      "curl / httpie (manual requests)",
      "ffuf / gobuster / feroxbuster (content discovery)",
      "sqlmap (automated SQL injection)",
      "jwt_tool / jwt.io (JWT inspection and forgery)",
      "git-dumper / GitTools (exposed .git recovery)",
      "Browser DevTools (network + console + storage tabs)",
      "wfuzz (parameter and value fuzzing)",
      "tplmap (SSTI exploitation)",
      "nosqlmap (NoSQL injection)",
    ],
    tips: [
      "Read every HTTP response fully, including headers and comments in HTML — flags hide there often",
      "Cookies and localStorage frequently carry more state than the visible UI implies",
      "If the app is slow to respond to one input, that's a strong signal for time-based blind injection",
      "Always check for an API behind the UI (look at XHR/fetch calls in DevTools network tab)",
      "Source code leaks (git, backups, .env) are the fastest path to the flag when available",
    ],
  },

  crypto: {
    description:
      "Cryptography challenges give you ciphertext, a scheme, or an implementation and ask " +
      "you to break confidentiality or forge integrity — from toy substitution ciphers to " +
      "flawed RSA and broken protocol logic.",
    commonChallenges: [
      "Classical cipher (Caesar, Vigenere, substitution, transposition)",
      "RSA with small/shared/weak primes (Fermat factorization, common modulus)",
      "RSA with small public exponent and no padding (Hastad's broadcast attack)",
      "XOR cipher with a repeating or single-byte key",
      "AES in ECB mode revealing repeated plaintext blocks",
      "Padding oracle attack against CBC mode",
      "Weak or predictable PRNG (seeded with time(), LCG, Mersenne Twister)",
      "Hash length extension attack (MD5/SHA1 without HMAC)",
      "Elliptic curve issues (small order, invalid curve, nonce reuse in ECDSA)",
      "Diffie-Hellman with a small or composite modulus",
      "One-time pad reused across multiple messages (many-time pad)",
      "Custom/homebrew crypto with an exploitable mathematical flaw",
      "Hash collision or preimage challenges against weak hash functions",
    ],
    techniques: [
      "Identify the scheme first: look at key size, ciphertext length, and any given source code",
      "For classical ciphers, run frequency analysis and try every shift/key length before guessing",
      "For RSA, always try to factor n first (factordb.com, Fermat, Pollard's rho) before anything fancy",
      "Check if n is shared across multiple ciphertexts (common modulus attack) or e is very small",
      "For ECB mode, look for repeating 16-byte blocks in the ciphertext — that confirms ECB",
      "For CBC, test if the server leaks padding-valid/invalid to mount a padding oracle attack",
      "For nonce-based schemes, check if the same nonce/IV is reused across messages (XOR them together)",
      "Reproduce the exact key-derivation/encryption steps locally in a script before attacking",
      "For PRNG challenges, recover the seed/state from leaked outputs, then predict future outputs",
      "For signature schemes, check for nonce reuse (k reuse leaks the private key in ECDSA/DSA)",
      "Always brute force small keyspaces (single-byte XOR, 4-digit PINs) before anything clever",
    ],
    tools: [
      "CyberChef (recipe-based decode/analysis, invaluable for quick pivots)",
      "Python + pycryptodome / sympy (custom scripts, factoring, modular arithmetic)",
      "RsaCtfTool (automated RSA attacks)",
      "SageMath (heavy number theory: lattice reduction, elliptic curves)",
      "openssl (inspect keys/certs, quick encrypt/decrypt tests)",
      "factordb.com (lookup known factorizations of n)",
      "hashcat / John the Ripper (hash and password cracking)",
      "xortool (single/multi-byte XOR key recovery)",
    ],
    tips: [
      "Never assume a 'weird' number is random — CTF crypto challenges almost always have a deliberate flaw",
      "Small e (e=3) plus no padding is the single most common RSA mistake to look for first",
      "If you're given source code for the crypto, the vulnerability is in that code, not the math itself",
      "Keep ciphertext, plaintext-guess, and key candidates in a script rather than doing math by hand",
    ],
  },

  forensics: {
    description:
      "Forensics challenges hand you an artifact — a file, disk image, memory dump, or " +
      "network capture — and ask you to recover hidden or deleted data from it.",
    commonChallenges: [
      "Corrupted or extension-mismatched file needing header repair",
      "Data hidden in file metadata (EXIF, PDF metadata, document properties)",
      "Deleted files recoverable from a disk/filesystem image",
      "Flag hidden inside a PCAP (extract a transferred file or a plaintext protocol)",
      "Memory dump analysis (recover processes, passwords, or injected code)",
      "Steganography inside an image, audio, or video file",
      "Archive with a nested/zip-bomb structure or password protection",
      "Git repository history containing a since-removed flag",
      "Log file analysis to reconstruct an attacker's timeline",
      "Recovering a flag split across multiple file fragments (file carving)",
    ],
    techniques: [
      "Always run `file` first — never trust the given extension",
      "Check magic bytes/hex header against the real file signature (PNG, ZIP, PDF, etc.)",
      "Extract and read all metadata: EXIF for images, exiftool for almost everything else",
      "For PCAPs, use Follow TCP/UDP Stream in Wireshark and export objects (File > Export Objects)",
      "For archives, try common passwords, the challenge name, and known-plaintext zip attacks",
      "Binwalk the file for embedded archives/images (`binwalk -e`) — nesting is extremely common",
      "For memory dumps, identify the OS/profile first, then pull processes, network connections, and clipboard",
      "For disk images, mount read-only and check unallocated space / deleted inode recovery",
      "Diff a 'before' and 'after' version of a file (if both given) byte by byte",
      "Check every frame/channel of audio/video for a hidden signal (spectrogram for audio!)",
      "Search the whole git history, not just HEAD (`git log --all`, `git show <commit>`)",
    ],
    tools: [
      "file / exiftool / binwalk (identification and metadata)",
      "Wireshark / tshark (packet capture analysis)",
      "Autopsy / The Sleuth Kit (disk forensics)",
      "Volatility3 (memory forensics)",
      "foremost / scalpel / photorec (file carving)",
      "Audacity / Sonic Visualiser (audio spectrogram analysis)",
      "GIMP / stegsolve / zsteg (image layer/LSB inspection)",
      "7-Zip / John the Ripper zip2john (archive password recovery)",
      "git log / gitk / git-secrets-scan (git history mining)",
    ],
    tips: [
      "Run `strings` and `file` on absolutely everything before doing anything more complex",
      "Rename the extension to match the true magic bytes — many tools refuse mismatched files",
      "Always check EXIF/metadata even on 'boring' looking images — it's the single cheapest win",
      "If a zip needs a password, check the challenge description/name for the password first",
    ],
  },

  reversing: {
    description:
      "Reverse engineering challenges give you a compiled binary (or bytecode) and ask you " +
      "to understand its logic well enough to extract a flag, bypass a check, or produce " +
      "valid input.",
    commonChallenges: [
      "Simple 'crackme' that validates a serial/flag via string comparison",
      "Flag built at runtime through XOR/arithmetic obfuscation on a hardcoded array",
      "Anti-debugging tricks (ptrace checks, timing checks, VM detection)",
      "Packed or stripped binary requiring unpacking before analysis",
      "Custom virtual machine / bytecode interpreter to reverse",
      "Android APK requiring decompilation (Java/Kotlin or native .so)",
      ".NET or Java bytecode that decompiles cleanly but has obfuscated logic",
      "Firmware or embedded binary for an unusual architecture (ARM, MIPS)",
      "Algorithm-recovery challenge: reimplement the check logic to compute the valid input",
    ],
    techniques: [
      "Run `file` and `checksec` first to learn architecture, arch bits, and protections",
      "Run `strings` for hardcoded flags, format strings, and library hints before disassembling",
      "Open in a disassembler and locate `main`, then trace to the comparison/validation routine",
      "Rename variables/functions as you understand them to build a readable mental model",
      "For simple checks, patch the conditional jump or just extract the compare value directly",
      "For XOR/arithmetic-obfuscated flags, recreate the transform in Python rather than by hand",
      "Use a decompiler (Ghidra/IDA Hex-Rays) to read pseudo-C instead of raw assembly when possible",
      "Dynamically trace with a debugger and set breakpoints right before/after the check runs",
      "For packed binaries, run under a debugger and dump memory after the unpacking stub finishes",
      "For mobile apps, decompile with jadx/apktool and grep for suspicious strings and native calls",
      "When stuck, brute force short/keyspace-limited checks with a script driving the binary",
    ],
    tools: [
      "Ghidra (free disassembler/decompiler)",
      "IDA Pro / IDA Free (disassembler/decompiler)",
      "radare2 / Cutter (disassembler with scripting)",
      "gdb + pwndbg/gef/peda (dynamic debugging)",
      "strings / file / checksec (quick static triage)",
      "jadx / apktool / dex2jar (Android reversing)",
      "dnSpy / ILSpy (.NET decompilation)",
      "x64dbg (Windows dynamic analysis)",
      "Frida (dynamic instrumentation/hooking)",
    ],
    tips: [
      "Static analysis (read the code) and dynamic analysis (run/debug it) are complementary — use both",
      "Never hand-solve an obfuscated transform; script it so you can iterate quickly",
      "Ghidra's decompiler view is usually faster to read than raw assembly for logic recovery",
      "Set a breakpoint right at the strcmp/memcmp near the flag check — the compared value is your answer",
    ],
  },

  pwn: {
    description:
      "Binary exploitation ('pwn') challenges give you a vulnerable network service or " +
      "binary and ask you to gain code execution or leak memory to read a flag, usually " +
      "via memory-corruption bugs.",
    commonChallenges: [
      "Classic stack buffer overflow overwriting the return address",
      "Format string vulnerability to leak memory or write arbitrary values",
      "Heap exploitation (use-after-free, double-free, heap overflow)",
      "Return-Oriented Programming (ROP) to bypass NX/DEP",
      "Integer overflow/underflow leading to a buffer overflow",
      "Off-by-one / off-by-null overwrite",
      "Race condition (TOCTOU) in a setuid or privileged binary",
      "Type confusion in a scripting language interpreter (browser/JS engine pwn)",
      "Return-to-libc to bypass a non-executable stack without ROP gadgets",
    ],
    techniques: [
      "Run `checksec` first to see which mitigations are on (NX, PIE, canary, RELRO)",
      "Fuzz the input lightly to find the crash offset, then use pattern_create/pattern_offset to confirm it",
      "If a stack canary is present, find a leak (format string, info leak) before attempting overflow",
      "If PIE/ASLR is on, leak a pointer first (GOT, libc address) to compute the real base address",
      "Build the exploit incrementally in pwntools: confirm control of RIP before chaining gadgets",
      "For ROP, find gadgets with a tool rather than reading raw disassembly by hand",
      "For format strings, use %p/%x to map the stack, then %n to write once you know the offset",
      "For heap bugs, understand the allocator's chunk layout before attempting corruption",
      "Test the exploit locally against the exact same libc version as the remote before firing at it",
      "Always write exploits as a script (pwntools) so they're reproducible against the real remote",
    ],
    tools: [
      "pwntools (Python exploit development framework)",
      "gdb + pwndbg/gef/peda (dynamic debugging with pwn-focused enhancements)",
      "checksec (binary protection/mitigation report)",
      "ROPgadget / ropper (ROP gadget discovery)",
      "one_gadget (finds one-shot execve gadgets in libc)",
      "pattern_create / pattern_offset (cyclic pattern crash-offset discovery)",
      "libc-database (identify libc version from leaked addresses/symbols)",
      "qemu (emulation for non-native architecture binaries)",
    ],
    tips: [
      "Always match the remote's libc version locally — offsets differ between libc builds",
      "Confirm you control the instruction pointer before building anything more complex",
      "Keep an exploit dev log of offsets/addresses you've found — you'll need them again after a crash",
      "Read the binary's protections before planning an approach: canary and NX shape the whole strategy",
    ],
  },

  misc: {
    description:
      "Miscellaneous challenges are the catch-all category: programming puzzles, esoteric " +
      "encodings, trivia, sandboxes/jails, and anything that doesn't fit the other five.",
    commonChallenges: [
      "Encoding puzzle chaining multiple layers (base64 -> hex -> rot13 -> ...)",
      "Sandbox escape / restricted shell (rbash, Python jail, container escape)",
      "Programming challenge requiring a script to compute the answer within a time limit",
      "QR code, barcode, or visual puzzle containing an encoded flag",
      "Esoteric programming language challenge (Brainfuck, Whitespace, Malbolge)",
      "Server interaction challenge via raw netcat/socket protocol",
      "OSINT-adjacent trivia challenge about the CTF itself or its organizers",
      "ZIP/archive puzzle requiring an unusual extraction technique",
    ],
    techniques: [
      "Identify each encoding layer one at a time — don't guess the whole chain at once",
      "For jail/sandbox escapes, enumerate what characters/functions/modules are blocked, then find the gap",
      "For a networked puzzle, connect with netcat first and read the prompt/protocol carefully",
      "Automate repetitive or timed interactions with pwntools' `remote()` or a small socket script",
      "For esoteric languages, find or write a small interpreter rather than tracing by hand",
      "Try CyberChef's 'Magic' wand operation as a first pass on unknown encodings",
      "Re-read the challenge prompt and filename literally — misc flags often hide in a throwaway detail",
    ],
    tools: [
      "CyberChef (multi-layer encode/decode 'Magic' detection)",
      "netcat / socat (raw network interaction)",
      "pwntools (scripted remote interaction)",
      "Python (glue language for almost every misc puzzle)",
      "online esoteric-language interpreters (Brainfuck, Whitespace, etc.)",
      "qrencode / zbarimg (QR/barcode decode)",
    ],
    tips: [
      "Misc is intentionally unpredictable — read the prompt twice before touching a tool",
      "If it feels like it needs a script, it does; don't hand-decode a 5-layer encoding chain",
      "Check the challenge's file name and any attached hints; misc puzzles often over-explain in the title",
    ],
  },

  osint: {
    description:
      "Open Source Intelligence (OSINT) challenges ask you to find publicly available " +
      "information about a person, organization, image, or location using only " +
      "legitimate public sources.",
    commonChallenges: [
      "Identify a location from a photo (geolocation/geoguessing)",
      "Find a person's social media accounts from a username or photo",
      "Reverse image search to find the original source of a picture",
      "Extract EXIF GPS coordinates from an unmodified photo",
      "Find information about a domain/organization (WHOIS, DNS history, certificate transparency)",
      "Identify a specific building, sign, or landmark from partial visual clues",
      "Trace a username across platforms to build a profile",
      "Find an archived/deleted version of a web page or social media post",
    ],
    techniques: [
      "Check image metadata (EXIF) first — many images retain GPS coordinates unmodified",
      "Reverse image search with multiple engines; each indexes different sources",
      "For geolocation, look at road markings, license plates, signage language, vegetation, and sun angle",
      "Cross-reference a username across platforms using dedicated username-search tools",
      "Use the Wayback Machine / archive.today for deleted or edited pages",
      "Check certificate transparency logs (crt.sh) for subdomains of a target domain",
      "Search image crops/zoomed regions separately — a small sign or logo is often the key clue",
      "Correlate multiple weak clues (language, architecture style, currency, plants) rather than relying on one",
    ],
    tools: [
      "Google/Bing/Yandex reverse image search",
      "exiftool (image metadata extraction)",
      "Wayback Machine / archive.today (historical page snapshots)",
      "Sherlock / WhatsMyName (username enumeration across platforms)",
      "crt.sh (certificate transparency search)",
      "Google Earth / Google Street View (geolocation verification)",
      "Shodan / Censys (internet-connected device/service search)",
      "whois / dig (domain and DNS intelligence)",
    ],
    tips: [
      "Never guess a location from a single clue — triangulate at least two independent details",
      "Yandex tends to outperform Google for reverse image geolocation searches",
      "Always check if metadata survived upload — many platforms strip EXIF, but not all do",
      "OSINT is legal, passive information gathering only — never attempt to access private systems",
    ],
  },
};

// ---------------------------------------------------------------------------------------
// COMMON_FLAG_FORMATS — recognize a flag once you're staring at one
// ---------------------------------------------------------------------------------------
const COMMON_FLAG_FORMATS = [
  { name: "generic", regex: /flag\{[^}]+\}/i, description: "Generic lowercase flag wrapper used by most independent CTFs", example: "flag{this_is_a_flag}" },
  { name: "CTF", regex: /CTF\{[^}]+\}/, description: "Generic uppercase CTF wrapper", example: "CTF{example_flag_here}" },
  { name: "FLAG", regex: /FLAG\{[^}]+\}/, description: "All-caps FLAG wrapper, common in beginner-friendly CTFs", example: "FLAG{ALL_CAPS_EXAMPLE}" },
  { name: "picoCTF", regex: /picoCTF\{[^}]+\}/, description: "picoCTF's signature flag format", example: "picoCTF{sample_flag_123}" },
  { name: "HTB", regex: /HTB\{[^}]+\}/, description: "Hack The Box challenge flag format", example: "HTB{s4mpl3_fl4g}" },
  { name: "THM", regex: /THM\{[^}]+\}/, description: "TryHackMe challenge flag format", example: "THM{sample_flag}" },
  { name: "DUCTF", regex: /DUCTF\{[^}]+\}/, description: "DownUnderCTF flag format", example: "DUCTF{example_flag}" },
  { name: "CSAW", regex: /csaw\{[^}]+\}/i, description: "CSAW CTF flag format", example: "csaw{example_flag}" },
  { name: "corctf", regex: /corctf\{[^}]+\}/i, description: "corCTF flag format", example: "corctf{example_flag}" },
  { name: "hackthebox_htb_lower", regex: /htb\{[^}]+\}/i, description: "Lowercase variant of the HTB flag format", example: "htb{example_flag}" },
  { name: "google_ctf", regex: /CTF\{[^}]+\}|google\{[^}]+\}/i, description: "Google CTF flag format", example: "CTF{google_example}" },
  { name: "hackpack", regex: /hackpack\{[^}]+\}/i, description: "HackPack CTF flag format", example: "hackpack{example_flag}" },
  { name: "justCTF", regex: /justCTF\{[^}]+\}/i, description: "justCTF flag format", example: "justCTF{example_flag}" },
  { name: "midnightsun", regex: /midnight\{[^}]+\}/i, description: "Midnight Sun CTF flag format", example: "midnight{example_flag}" },
  { name: "uiuctf", regex: /uiuctf\{[^}]+\}/i, description: "UIUCTF flag format", example: "uiuctf{example_flag}" },
  { name: "wctf", regex: /wctf\{[^}]+\}/i, description: "Generic 'wctf' style wrapper seen in various regional CTFs", example: "wctf{example_flag}" },
  { name: "sha256_hash", regex: /\b[a-f0-9]{64}\b/i, description: "Raw SHA-256 hex digest, sometimes used directly as a flag/token", example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { name: "md5_hash", regex: /\b[a-f0-9]{32}\b/i, description: "Raw MD5 hex digest, occasionally used as a flag or intermediate token", example: "d41d8cd98f00b204e9800998ecf8427e" },
  { name: "uuid_flag", regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i, description: "UUID-shaped flag/token used by some web/misc challenges", example: "550e8400-e29b-41d4-a716-446655440000" },
];

// ---------------------------------------------------------------------------------------
// CIPHER_IDENTIFIERS — pattern-based detection for classic and CTF-favorite encodings
// ---------------------------------------------------------------------------------------
const CIPHER_IDENTIFIERS = [
  {
    name: "Base64",
    description: "Standard Base64 encoding using A-Z, a-z, 0-9, +, / with = padding",
    detect: (s) => /^[A-Za-z0-9+/]{8,}={0,2}$/.test(s.trim()) && s.trim().length % 4 === 0,
    decode: "Buffer.from(str, 'base64').toString() in Node, or `base64 -d` on the CLI",
    characteristics: ["length is a multiple of 4", "may end in = or == padding", "no characters outside A-Za-z0-9+/="],
  },
  {
    name: "Base32",
    description: "Base32 encoding using A-Z and 2-7, often padded with =",
    detect: (s) => /^[A-Z2-7]{8,}={0,6}$/.test(s.trim()),
    decode: "base32 -d on CLI, or a base32 decode recipe in CyberChef",
    characteristics: ["only uppercase letters A-Z and digits 2-7", "length is a multiple of 8 when padded"],
  },
  {
    name: "Base16 / Hex",
    description: "Hexadecimal encoding using only 0-9 and a-f/A-F",
    detect: (s) => /^[0-9a-fA-F]{8,}$/.test(s.trim()) && s.trim().length % 2 === 0,
    decode: "Buffer.from(str, 'hex').toString() in Node, or `xxd -r -p` on the CLI",
    characteristics: ["even length", "only hex digits 0-9a-fA-F", "often groups nicely into byte pairs"],
  },
  {
    name: "ROT13",
    description: "Caesar cipher with a fixed shift of 13, self-inverse",
    detect: (s) => /^[a-zA-Z\s.,!?'"0-9{}_-]+$/.test(s) && /[a-zA-Z]/.test(s),
    decode: "Shift each letter 13 places; applying ROT13 twice returns the original text",
    characteristics: ["looks like garbled but pronounceable English", "punctuation and spacing preserved", "digits unaffected"],
  },
  {
    name: "Caesar cipher",
    description: "Simple substitution shifting every letter by a fixed amount (not necessarily 13)",
    detect: (s) => /^[a-zA-Z\s.,!?'"0-9{}_-]+$/.test(s) && /[a-zA-Z]/.test(s),
    decode: "Brute force all 25 shifts and read off the one that produces plaintext",
    characteristics: ["letter frequency shape matches English but shifted", "word lengths/spacing preserved", "short keyspace (25 shifts) so brute force is trivial"],
  },
  {
    name: "Vigenere cipher",
    description: "Polyalphabetic substitution using a repeating keyword to vary the shift per letter",
    detect: (s) => /^[a-zA-Z\s]+$/.test(s) && s.replace(/\s/g, "").length > 20,
    decode: "Use Kasiski examination / index of coincidence to find key length, then frequency analysis per column",
    characteristics: ["letters only, longer ciphertext needed to analyze", "flat-looking frequency distribution compared to Caesar"],
  },
  {
    name: "Atbash cipher",
    description: "Substitution cipher that reverses the alphabet (A<->Z, B<->Y, ...)",
    detect: (s) => /^[a-zA-Z\s.,!?'"0-9{}_-]+$/.test(s) && /[a-zA-Z]/.test(s),
    decode: "Map each letter to its mirror position in the alphabet; self-inverse like ROT13",
    characteristics: ["ancient/simple substitution, often called out by name in the challenge", "self-inverse (apply twice to undo)"],
  },
  {
    name: "Morse code",
    description: "Encodes characters as sequences of dots and dashes",
    detect: (s) => /^[.\-\/\s]+$/.test(s.trim()) && /[.\-]/.test(s),
    decode: "Split on spaces for letters and slashes for words, map via the standard Morse table",
    characteristics: ["only dots, dashes, slashes, and spaces", "grouped in short clusters of 1-4 symbols per letter"],
  },
  {
    name: "Binary",
    description: "Text represented as 0/1 byte sequences",
    detect: (s) => /^[01\s]{8,}$/.test(s.trim()) && s.replace(/\s/g, "").length % 8 === 0,
    decode: "Split into 8-bit groups, convert each to a char code, then to a character",
    characteristics: ["only 0s and 1s (plus whitespace)", "total bit count divisible by 8"],
  },
  {
    name: "Octal",
    description: "Text represented as base-8 byte sequences",
    detect: (s) => /^[0-7\s]{6,}$/.test(s.trim()) && /^([0-7]{2,3}\s*)+$/.test(s.trim()),
    decode: "Split into groups, parseInt(group, 8), then convert to character",
    characteristics: ["only digits 0-7", "grouped in 2-3 digit clusters separated by spaces"],
  },
  {
    name: "Rail Fence cipher",
    description: "Transposition cipher writing text in a zigzag across N rails then reading by row",
    detect: (s) => /^[a-zA-Z]+$/.test(s.replace(/\s/g, "")) && s.replace(/\s/g, "").length > 10,
    decode: "Try rail counts 2 through ~8, reconstruct the zigzag grid, and read diagonally",
    characteristics: ["letters only, same letter frequency as the plaintext (it's a transposition, not substitution)", "no recognizable words at first glance despite normal letter distribution"],
  },
  {
    name: "Bacon's cipher",
    description: "Steganographic cipher encoding letters as 5-bit sequences of two symbols (traditionally A/B)",
    detect: (s) => /^[AaBb\s]{15,}$/.test(s.trim()) || /^[01\s]{5}([01\s]{5})+$/.test(s.trim()),
    decode: "Split into groups of 5 symbols, map A/B (or 0/1) patterns to letters via the Baconian table",
    characteristics: ["only two distinct symbols repeated in groups of 5", "sometimes hidden via font/case styling in the original text instead of literal A/B"],
  },
  {
    name: "XOR cipher",
    description: "Single-byte or repeating-key XOR applied to raw bytes, usually then hex/base64 encoded",
    detect: (s) => /^[0-9a-fA-F]{8,}$/.test(s.trim()) && s.trim().length % 2 === 0,
    decode: "Brute force single-byte keys (256 tries) or use frequency-based key-length recovery for repeating-key XOR",
    characteristics: ["appears as hex or base64 ciphertext with no obvious structure", "XORing two ciphertexts with the same key cancels the key, revealing plaintext XOR plaintext"],
  },
  {
    name: "URL encoding",
    description: "Percent-encoding of reserved/non-ASCII characters, common in web challenge payloads",
    detect: (s) => /%[0-9a-fA-F]{2}/.test(s),
    decode: "decodeURIComponent(str) in JS, or `urllib.parse.unquote` in Python",
    characteristics: ["contains %XX sequences", "often mixed with normal ASCII text"],
  },
  {
    name: "HTML entities",
    description: "Characters encoded as &#nnn; (decimal), &#xhhh; (hex), or named entities like &amp;",
    detect: (s) => /&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(s),
    decode: "Use an HTML entity decoder (browser DOM trick, or a library / CyberChef recipe)",
    characteristics: ["contains &...; sequences", "often found embedded in scraped HTML/XML"],
  },
  {
    name: "JWT (JSON Web Token)",
    description: "Three base64url segments (header.payload.signature) separated by dots",
    detect: (s) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s.trim()),
    decode: "Base64url-decode the first two dot-separated segments to reveal header and payload JSON",
    characteristics: ["exactly two dots splitting three base64url segments", "decoded header typically starts with {\"alg\":", "used for web/crypto category auth challenges"],
  },
  {
    name: "Brainfuck",
    description: "Esoteric programming language using only 8 symbols: > < + - . , [ ]",
    detect: (s) => /^[><+\-.,\[\]\s]+$/.test(s.trim()) && /[><+\-.,\[\]]/.test(s),
    decode: "Run through any Brainfuck interpreter to get printed output",
    characteristics: ["only the 8 characters > < + - . , [ ]", "often contains balanced/nested square brackets"],
  },
  {
    name: "Ook!",
    description: "Brainfuck variant using only the words Ook., Ook?, and Ook! in pairs",
    detect: (s) => /^(Ook[.?!]\s*)+$/i.test(s.trim()),
    decode: "Map each Ook pair back to a Brainfuck instruction, then run through a Brainfuck interpreter",
    characteristics: ["only repetitions of the word 'Ook' followed by ., ?, or !", "always appears in pairs of two Ook tokens"],
  },
  {
    name: "Base85 / ASCII85",
    description: "Denser binary-to-text encoding than Base64, using a wider printable character range",
    detect: (s) => /^<~.*~>$/.test(s.trim()) || (/^[!-u]{5,}$/.test(s.trim()) && !/^[A-Za-z0-9+/=]+$/.test(s.trim())),
    decode: "Use an ASCII85/Base85 decoder (Python's base64.a85decode, or a CyberChef recipe)",
    characteristics: ["often wrapped in <~ and ~> delimiters (Adobe variant)", "wider character range than Base64, including punctuation"],
  },
  {
    name: "Base58",
    description: "Bitcoin-style encoding excluding visually ambiguous characters (0, O, I, l)",
    detect: (s) => /^[1-9A-HJ-NP-Za-km-z]{10,}$/.test(s.trim()),
    decode: "Use a Base58 decoder library (common in crypto/blockchain-themed challenges)",
    characteristics: ["alphanumeric but never contains 0, O, I, or lowercase l", "common in blockchain/wallet-themed challenges"],
  },
  {
    name: "Quoted-printable",
    description: "MIME encoding representing non-ASCII bytes as =XX hex sequences",
    detect: (s) => /=[0-9A-F]{2}/.test(s) && /=\r?\n/.test(s) === false && /[a-zA-Z]/.test(s),
    decode: "Use a quoted-printable decoder (Python's quopri module, or CyberChef)",
    characteristics: ["mostly readable ASCII text interspersed with =XX escapes", "often found in raw email/MIME dumps"],
  },
  {
    name: "UUencoding",
    description: "Legacy Unix binary-to-text encoding, lines begin with 'begin' and end with 'end'",
    detect: (s) => /^begin\s+\d{3}\s+\S+/m.test(s) && /^end$/m.test(s),
    decode: "Use `uudecode` on the CLI or a UUdecode library",
    characteristics: ["starts with a line like 'begin 644 filename'", "ends with a lone 'end' line", "each data line starts with a length-encoding character"],
  },
  {
    name: "Tap code",
    description: "Prisoner's cipher encoding letters as pairs of tap counts on a 5x5 Polybius-style grid",
    detect: (s) => /^[.\s]{10,}$/.test(s.trim()) && /\.\.?\s+\.\.?/.test(s),
    decode: "Group taps in pairs (row, column) and map through a 5x5 grid (I/J share a cell)",
    characteristics: ["represented as groups of dots/taps separated by pauses", "typically 25-letter grid with I and J merged"],
  },
];

// ---------------------------------------------------------------------------------------
// STEGANOGRAPHY_CHECKS — the standard stego toolbox
// ---------------------------------------------------------------------------------------
const STEGANOGRAPHY_CHECKS = [
  {
    name: "File type / magic byte mismatch",
    description: "Confirm the file's true type doesn't match its extension before anything else",
    fileTypes: ["any"],
    tool: "file",
    command: "file suspicious_file",
    indicators: ["reported type differs from the extension", "unusual or unrecognized signature"],
  },
  {
    name: "Metadata inspection",
    description: "Check EXIF/metadata fields for hidden text, GPS data, or comments",
    fileTypes: ["jpg", "jpeg", "png", "tiff", "pdf", "docx"],
    tool: "exiftool",
    command: "exiftool suspicious_file",
    indicators: ["unusually long comment/description fields", "suspicious 'Software' or 'Author' fields", "embedded base64-looking strings"],
  },
  {
    name: "Embedded file / archive carving",
    description: "Search the file for other file signatures hidden after the legitimate EOF marker",
    fileTypes: ["png", "jpg", "gif", "bmp", "any"],
    tool: "binwalk",
    command: "binwalk -e suspicious_file",
    indicators: ["binwalk reports multiple signatures at different offsets", "file size far larger than expected for its visible content"],
  },
  {
    name: "LSB (Least Significant Bit) analysis",
    description: "Extract data hidden in the least significant bits of pixel color channels",
    fileTypes: ["png", "bmp", "gif"],
    tool: "zsteg",
    command: "zsteg -a suspicious_file.png",
    indicators: ["visually normal image but zsteg reports readable text/patterns in bit planes", "unusually smooth or noisy specific color-channel bit planes"],
  },
  {
    name: "Bit-plane visualization",
    description: "Manually inspect each color-channel bit plane for hidden shapes or text",
    fileTypes: ["png", "bmp", "gif", "jpg"],
    tool: "stegsolve",
    command: "java -jar stegsolve.jar",
    indicators: ["a specific bit plane reveals a shape, QR code, or text invisible in the normal view"],
  },
  {
    name: "Strings extraction",
    description: "Pull all printable strings out of a binary/media file to spot plaintext flags or hints",
    fileTypes: ["any"],
    tool: "strings",
    command: "strings -n 8 suspicious_file",
    indicators: ["a flag-shaped substring appears directly in the output", "suspicious base64/hex blobs mixed in with binary noise"],
  },
  {
    name: "Steghide extraction",
    description: "Attempt to extract data hidden with the steghide tool (JPEG/BMP/WAV/AU)",
    fileTypes: ["jpg", "jpeg", "bmp", "wav", "au"],
    tool: "steghide",
    command: "steghide extract -sf suspicious_file.jpg",
    indicators: ["extraction succeeds with an empty or challenge-hinted passphrase", "file was explicitly flagged as steghide-hidden by challenge text"],
  },
  {
    name: "OutGuess detection",
    description: "Check for data hidden with the OutGuess steganography tool",
    fileTypes: ["jpg", "jpeg", "png"],
    tool: "outguess",
    command: "outguess -r suspicious_file.jpg output.txt",
    indicators: ["successful extraction produces readable output", "file statistically resembles OutGuess-modified JPEGs"],
  },
  {
    name: "Audio spectrogram analysis",
    description: "Visualize an audio file's frequency spectrum to reveal hidden images/text drawn into the signal",
    fileTypes: ["wav", "mp3", "flac"],
    tool: "Sonic Visualiser / Audacity",
    command: "audacity suspicious_file.wav  # then View > Spectrogram",
    indicators: ["spectrogram view reveals text, a QR code, or shapes not audible to the ear"],
  },
  {
    name: "Audio LSB / channel analysis",
    description: "Check least significant bits of audio samples, or hidden data in a second (right) channel",
    fileTypes: ["wav", "flac"],
    tool: "sox / custom script",
    command: "sox suspicious_file.wav -n stat",
    indicators: ["left/right channels differ unexpectedly", "sample statistics look artificially uniform (indicating embedded data)"],
  },
  {
    name: "PDF object/stream inspection",
    description: "Inspect PDF internal objects and streams for embedded files, scripts, or hidden text layers",
    fileTypes: ["pdf"],
    tool: "pdf-parser / qpdf",
    command: "pdf-parser.py --search Flag suspicious_file.pdf",
    indicators: ["JavaScript objects embedded in the PDF", "extra embedded file streams (/EmbeddedFile)", "text layer hidden behind an image layer"],
  },
  {
    name: "Zip/Archive comment and slack space",
    description: "Check archive comment fields and trailing bytes after the archive's logical end",
    fileTypes: ["zip", "any"],
    tool: "zipinfo / unzip",
    command: "unzip -v suspicious_file.zip",
    indicators: ["non-empty archive comment field", "extra bytes after the End Of Central Directory record"],
  },
  {
    name: "QR code / barcode scan",
    description: "Check images for embedded QR codes or barcodes, including ones hidden in noise or a bit plane",
    fileTypes: ["png", "jpg", "bmp"],
    tool: "zbarimg",
    command: "zbarimg suspicious_file.png",
    indicators: ["a scannable code renders after bit-plane extraction or contrast adjustment"],
  },
  {
    name: "Whitespace steganography",
    description: "Check text files for hidden data encoded as trailing spaces/tabs per line",
    fileTypes: ["txt", "any text"],
    tool: "snow / custom script",
    command: "snow -C suspicious_file.txt",
    indicators: ["lines have inconsistent or unusual trailing whitespace", "file looks like plain text but has an unusually large size for its visible content"],
  },
  {
    name: "Image dimension / palette anomaly check",
    description: "Compare an image's reported dimensions/palette to the actual pixel data for hidden extra rows",
    fileTypes: ["png", "bmp", "gif"],
    tool: "pngcheck / ImageMagick identify",
    command: "pngcheck -v suspicious_file.png",
    indicators: ["height/width field manipulated to hide extra image data below the visible crop", "chunk CRC errors reported by pngcheck"],
  },
  {
    name: "Video frame-by-frame extraction",
    description: "Extract individual frames from a video to find a flag flashed briefly on screen",
    fileTypes: ["mp4", "avi", "mkv"],
    tool: "ffmpeg",
    command: "ffmpeg -i suspicious_file.mp4 frames/out%04d.png",
    indicators: ["a single frame contains readable text not visible during normal playback speed"],
  },
];

// ---------------------------------------------------------------------------------------
// identifyChallenge(description) — score a free-text description against CTF_CATEGORIES
// ---------------------------------------------------------------------------------------

// Keyword weight tables per category (kept close to CTF_CATEGORIES so scoring stays honest)
const CATEGORY_KEYWORDS = {
  web: ["website", "http", "url", "login", "cookie", "sql", "injection", "xss", "sqli", "ssrf", "ssti",
    "server", "apache", "nginx", "php", "flask", "django", "api", "endpoint", "browser", "cors",
    "jwt", "session", "form", "upload", "idor", "xxe", "graphql", "webpage", "html", "burp"],
  crypto: ["cipher", "encrypt", "decrypt", "rsa", "aes", "xor", "hash", "key", "modulus", "prime",
    "vigenere", "caesar", "public key", "private key", "signature", "nonce", "padding", "ecb", "cbc",
    "elliptic", "curve", "ecdsa", "diffie", "hellman", "ciphertext", "plaintext", "encoding"],
  forensics: ["pcap", "wireshark", "memory dump", "disk image", "metadata", "exif", "recover",
    "deleted", "carve", "capture", "packet", "volatility", "artifact", "log file", "filesystem",
    "usb", "network traffic", "dump.raw", "image file", "corrupted"],
  reversing: ["binary", "disassemble", "reverse engineer", "crackme", "assembly", "ghidra", "ida",
    "decompile", "elf", "exe", "apk", "obfuscated", "serial", "license key", "strings", "gdb",
    "patch", "opcode", "bytecode", "packed"],
  pwn: ["buffer overflow", "shellcode", "exploit", "rop", "return address", "stack", "heap",
    "canary", "nx", "aslr", "libc", "format string", "use-after-free", "double free", "gadget",
    "segfault", "ret2libc", "pwntools", "netcat", "nc ", "remote service"],
  misc: ["puzzle", "esoteric", "brainfuck", "sandbox", "jail", "encoding chain", "trivia",
    "programming challenge", "netcat", "socket", "qr code", "whitespace", "interpreter"],
  osint: ["photo", "image location", "geolocate", "geolocation", "social media", "username",
    "reverse image", "public information", "instagram", "twitter", "facebook", "location",
    "landmark", "metadata gps", "domain history", "whois", "archived page"],
};

/**
 * Identify the most likely CTF category for a free-text challenge description.
 * @param {string} description
 * @returns {{category: string|null, confidence: number, matchedKeywords: string[], scores: Object<string, number>}}
 */
function identifyChallenge(description) {
  const text = String(description || "").toLowerCase();
  const scores = {};
  const matches = {};

  for (const category of Object.keys(CATEGORY_KEYWORDS)) {
    let score = 0;
    const matched = [];
    for (const kw of CATEGORY_KEYWORDS[category]) {
      if (text.includes(kw)) {
        score += kw.split(" ").length > 1 ? 2 : 1; // multi-word keywords are stronger signals
        matched.push(kw);
      }
    }
    scores[category] = score;
    matches[category] = matched;
  }

  // Also weight in flag-format hints — e.g. mentioning "jwt" strongly implies web/crypto
  let best = null;
  let bestScore = 0;
  for (const category of Object.keys(scores)) {
    if (scores[category] > bestScore) {
      bestScore = scores[category];
      best = category;
    }
  }

  const totalSignal = Object.values(scores).reduce((a, b) => a + b, 0) || 1;
  const confidence = best ? Math.min(1, bestScore / totalSignal + (bestScore >= 3 ? 0.15 : 0)) : 0;

  return {
    category: best,
    confidence: Number(confidence.toFixed(2)),
    matchedKeywords: best ? matches[best] : [],
    scores,
  };
}

// ---------------------------------------------------------------------------------------
// suggestApproach(category, clues) — turn a category + observed clues into a plan
// ---------------------------------------------------------------------------------------

// Clue -> extra hint mapping, layered on top of the category's baseline advice
const CLUE_HINTS = [
  { pattern: /\.pcap|wireshark|packet/i, hint: "Open the capture in Wireshark and use Follow Stream / Export Objects before anything else" },
  { pattern: /jwt|json web token/i, hint: "Decode the JWT header/payload first (base64url), then check alg and signature handling" },
  { pattern: /\.git|git repo/i, hint: "Pull the full git history (git log --all) — the flag is often in a removed commit" },
  { pattern: /rsa|public key|\.pem/i, hint: "Try factoring the modulus (factordb.com, Fermat/Pollard's rho) before anything more advanced" },
  { pattern: /ecb|repeating block/i, hint: "Look for repeated 16-byte ciphertext blocks — that confirms AES-ECB and enables block-shuffling attacks" },
  { pattern: /buffer overflow|segfault|crash/i, hint: "Confirm the exact crash offset with a cyclic pattern before touching the return address" },
  { pattern: /checksec|nx|canary|pie|aslr/i, hint: "Map out which protections are enabled first — that decides whether you need a leak before you can pwn it" },
  { pattern: /image|\.png|\.jpg|\.bmp/i, hint: "Run file + exiftool + binwalk on the image before manual bit-plane inspection" },
  { pattern: /audio|\.wav|\.mp3/i, hint: "Check the spectrogram view (Audacity/Sonic Visualiser) — many audio flags are drawn as visible text in frequency space" },
  { pattern: /base64|base32|encoded/i, hint: "Run the string through CyberChef's Magic wand — it will often chain-decode multiple layers automatically" },
  { pattern: /login|auth|password/i, hint: "Try SQLi auth bypass payloads and default credentials before anything more complex" },
  { pattern: /disassemb|binary|elf|exe/i, hint: "Start with strings + checksec, then open in Ghidra and locate main before diving into assembly" },
  { pattern: /geolocat|photo location|where.*taken/i, hint: "Cross-reference at least two independent visual clues (signage, vegetation, road markings) before committing to a location" },
  { pattern: /username|social media/i, hint: "Run the username through Sherlock/WhatsMyName to enumerate accounts across platforms" },
];

/**
 * Suggest a concrete approach for a category, refined by observed clues.
 * @param {string} category one of the CTF_CATEGORIES keys (case-insensitive)
 * @param {string[]} [clues] free-text clues observed about the challenge (filenames, prompt text, etc.)
 * @returns {{category: string, recommendedSteps: string[], toolsToUse: string[], commonPitfalls: string[], hints: string[]}}
 */
function suggestApproach(category, clues) {
  const key = String(category || "").toLowerCase();
  const cat = CTF_CATEGORIES[key];
  const clueList = Array.isArray(clues) ? clues : clues ? [String(clues)] : [];

  if (!cat) {
    return {
      category: key,
      recommendedSteps: [
        "Unrecognized category — re-run identifyChallenge() on the raw prompt text to classify it first",
        "In the meantime: run `file` and `strings` on any attached artifact, and read the prompt for a category giveaway",
      ],
      toolsToUse: ["file", "strings", "CyberChef"],
      commonPitfalls: ["Guessing a category and committing to one tool too early"],
      hints: [],
    };
  }

  const recommendedSteps = [
    `Read the prompt and any attached filename literally — ${key} challenges often hint at the exact vulnerability class`,
    ...cat.techniques.slice(0, 6),
    "Re-check the flag format expected by the CTF (see COMMON_FLAG_FORMATS) so you recognize success immediately",
  ];

  const hints = [];
  for (const c of clueList) {
    for (const { pattern, hint } of CLUE_HINTS) {
      if (pattern.test(c)) hints.push(hint);
    }
  }
  // De-duplicate while preserving order
  const seenHints = new Set();
  const dedupedHints = hints.filter((h) => (seenHints.has(h) ? false : (seenHints.add(h), true)));

  const commonPitfalls = {
    web: ["Fuzzing/guessing endlessly instead of reading page source and JS first", "Ignoring response headers and cookies", "Not checking for an exposed .git or backup file"],
    crypto: ["Jumping to exotic attacks before trying to factor/brute-force the obvious weak case", "Doing modular arithmetic by hand instead of scripting it", "Ignoring provided source code that reveals the exact flaw"],
    forensics: ["Trusting the given file extension instead of checking magic bytes", "Skipping metadata because the file 'looks' ordinary", "Not searching full git/log history, only the latest state"],
    reversing: ["Reading raw assembly when a decompiler view would be faster", "Hand-simulating an obfuscated transform instead of scripting it", "Not checking `strings` before spending an hour in the disassembler"],
    pwn: ["Attempting exploitation before checking protections with checksec", "Using the wrong libc version for offset calculations", "Skipping local testing before firing the exploit at the remote"],
    misc: ["Trying to solve a multi-layer encoding chain by hand instead of scripting it", "Overlooking a literal clue in the challenge title or filename", "Assuming it belongs to another category and thrashing between tools"],
    osint: ["Committing to a location/person from a single weak clue", "Assuming metadata was preserved without checking", "Skipping the Wayback Machine for content that may have been deleted or edited"],
  }[key] || [];

  return {
    category: key,
    recommendedSteps,
    toolsToUse: cat.tools.slice(),
    commonPitfalls,
    hints: dedupedHints.length ? dedupedHints : cat.tips.slice(0, 3),
  };
}

// ---------------------------------------------------------------------------------------
// Small internal helpers built on Node's crypto/builtin modules — used to sanity-check
// a guess before committing to a full decode pipeline elsewhere in Darknode.
// ---------------------------------------------------------------------------------------

/** Quick structural check that a string is plausibly valid base64 (does not verify padding semantics beyond length). */
function looksLikeBase64(s) {
  const t = String(s || "").trim();
  if (!t || t.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(t);
}

/** Quick structural check that a string is plausibly valid hex. */
function looksLikeHex(s) {
  const t = String(s || "").trim();
  return t.length > 0 && t.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(t);
}

/** Compute a short hash fingerprint (hex) of a string using Node's crypto module — useful for dedup/caching of decode attempts. */
function fingerprint(s, algo) {
  return crypto.createHash(algo || "sha256").update(String(s || ""), "utf8").digest("hex").slice(0, 16);
}

/** Run every registered cipher detector against a sample and return the ones that match. */
function detectCiphers(sample) {
  const s = String(sample || "");
  const hits = [];
  for (const c of CIPHER_IDENTIFIERS) {
    try {
      if (c.detect(s)) hits.push({ name: c.name, description: c.description, decode: c.decode, characteristics: c.characteristics });
    } catch (_e) {
      // A detector throwing on unusual input should never crash the caller.
    }
  }
  return hits;
}

/** Check a string against every known flag format and return the ones that match, with captured flag text. */
function findFlags(text) {
  const s = String(text || "");
  const found = [];
  for (const fmt of COMMON_FLAG_FORMATS) {
    const m = s.match(fmt.regex);
    if (m) found.push({ format: fmt.name, match: m[0], description: fmt.description });
  }
  return found;
}

module.exports = {
  CTF_CATEGORIES,
  COMMON_FLAG_FORMATS,
  CIPHER_IDENTIFIERS,
  STEGANOGRAPHY_CHECKS,
  identifyChallenge,
  suggestApproach,
  looksLikeBase64,
  looksLikeHex,
  fingerprint,
  detectCiphers,
  findFlags,
};
