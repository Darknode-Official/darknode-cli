"use strict";
// Best-effort desktop notification on every OS (was Linux-only notify-send, so
// macOS/Windows got only a bell). Fire-and-forget; errors are swallowed. The
// title/body never become script source: macOS gets them as osascript argv,
// Windows as environment variables, Linux as notify-send argv — so text the
// model wrote (an ask_user question) can't inject AppleScript or PowerShell.
function osNotify(title, body, opts) {
  const o = opts || {}, platform = o.platform || process.platform, spawn = o.spawn || require("child_process").spawn;
  const t = String(title || "").replace(/[\x00-\x1f\x7f]+/g, " ").slice(0, 120), b = String(body || "").replace(/[\x00-\x1f\x7f]+/g, " ").slice(0, 240);
  try {
    if (platform === "darwin") {
      spawn("osascript", ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", t, b], { stdio: "ignore" }).on("error", () => {});
    } else if (platform === "win32") {
      const ps = "$ErrorActionPreference='SilentlyContinue';Add-Type -AssemblyName System.Windows.Forms;" +
        "$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Information;" +
        "$n.BalloonTipTitle=$env:NEXUS_NOTIFY_TITLE;$n.BalloonTipText=$env:NEXUS_NOTIFY_BODY;$n.Visible=$true;$n.ShowBalloonTip(5000);Start-Sleep -Seconds 6;$n.Dispose()";
      spawn("powershell", ["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps], { stdio: "ignore", windowsHide: true, env: Object.assign({}, process.env, { NEXUS_NOTIFY_TITLE: t, NEXUS_NOTIFY_BODY: b }) }).on("error", () => {});
    } else {
      spawn("notify-send", ["--", t, b], { stdio: "ignore" }).on("error", () => {});
    }
  } catch (_) {}
}

module.exports = { osNotify };
