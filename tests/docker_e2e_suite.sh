#!/usr/bin/env bash
set -euo pipefail

CLENS="${1:-clens}"
ROOT="/tmp/clearlens-e2e"
rm -rf "$ROOT"
mkdir -p "$ROOT"

echo "=== [1/4] Rule Pack Validation & Unsafe Rule Rejection ==="
"$CLENS" rules list >/dev/null
"$CLENS" rules validate

BAD_RULE="$ROOT/bad_rule.toml"
cat > "$BAD_RULE" << 'EOF'
schema_version = 1
category = "system"
app_name = "Dangerous"
[[rules]]
id = "bad.ssh_wipe"
title = "Bad Rule"
kind = "glob"
risk = "safe"
default_checked = true
delete_mode = "permanent"
[rules.paths]
macos = ["~/.ssh/**"]
EOF

if "$CLENS" rules validate "$BAD_RULE" 2>/dev/null; then
  echo "FAIL: unsafe ~/.ssh/** rule was not rejected!"
  exit 1
fi
echo "PASS: unsafe rule properly rejected."

echo "=== [2/4] Simulated macOS Filesystem E2E (Safety + Dry-Run + Clean + Trash) ==="
MAC_HOME="$ROOT/macos_home"
export HOME="$MAC_HOME"
export XDG_DATA_HOME="$MAC_HOME/.local/share"

# Precious files that MUST NEVER be deleted
mkdir -p "$MAC_HOME/Desktop" "$MAC_HOME/.ssh"
echo "secret-key" > "$MAC_HOME/Desktop/important.key"
echo "ssh-priv" > "$MAC_HOME/.ssh/id_ed25519"

# WeChat caches (safe) vs WeChat Documents & DB (MUST KEEP)
WECHAT_MSG="$MAC_HOME/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4/user123/Message/MessageTemp/chat1"
mkdir -p "$WECHAT_MSG/Thumb" "$MAC_HOME/Library/Containers/com.tencent.xinWeChat/Data/Library/Caches/img" "$WECHAT_MSG/FileStorage/File"
dd if=/dev/zero of="$WECHAT_MSG/Thumb/old_thumb.jpg" bs=4096 count=4 status=none
touch -d "10 days ago" "$WECHAT_MSG/Thumb/old_thumb.jpg"
dd if=/dev/zero of="$MAC_HOME/Library/Containers/com.tencent.xinWeChat/Data/Library/Caches/img/tmp.bin" bs=4096 count=4 status=none
touch -d "10 days ago" "$MAC_HOME/Library/Containers/com.tencent.xinWeChat/Data/Library/Caches/img/tmp.bin"
echo "contract-data" > "$WECHAT_MSG/FileStorage/File/contract.pdf"
echo "sqlite-db" > "$WECHAT_MSG/chat.db"

# Chrome cache + symlink trap + Cookies (MUST KEEP)
CHROME_BASE="$MAC_HOME/Library/Caches/Google/Chrome/Default/Cache"
mkdir -p "$CHROME_BASE" "$MAC_HOME/Library/Application Support/Google/Chrome/Default"
dd if=/dev/zero of="$CHROME_BASE/data_0" bs=4096 count=8 status=none
ln -s "$MAC_HOME/Desktop" "$CHROME_BASE/symlink_trap"
echo "session-cookie" > "$MAC_HOME/Library/Application Support/Google/Chrome/Default/Cookies"

# iCloud dataless stub + 3x hardlink deduplication test inside Space Lens target
LENS_DIR="$MAC_HOME/LensSample"
mkdir -p "$LENS_DIR"
dd if=/dev/zero of="$LENS_DIR/blob_1.bin" bs=4096 count=8 status=none
ln "$LENS_DIR/blob_1.bin" "$LENS_DIR/blob_2.bin"
ln "$LENS_DIR/blob_1.bin" "$LENS_DIR/blob_3.bin"
dd if=/dev/zero of="$LENS_DIR/.CloudMovie.mov.icloud" bs=4096 count=2 status=none

# Cold vs Active developer projects
mkdir -p "$MAC_HOME/Projects/old-app/node_modules/pkg" "$MAC_HOME/Projects/active-app/node_modules/pkg"
echo '{}' > "$MAC_HOME/Projects/old-app/package.json"
dd if=/dev/zero of="$MAC_HOME/Projects/old-app/node_modules/pkg/index.js" bs=4096 count=6 status=none
touch -d "45 days ago" "$MAC_HOME/Projects/old-app/package.json" "$MAC_HOME/Projects/old-app"
echo '{}' > "$MAC_HOME/Projects/active-app/package.json"
dd if=/dev/zero of="$MAC_HOME/Projects/active-app/node_modules/pkg/index.js" bs=4096 count=6 status=none

# Old .dmg in Downloads (>60d) -> review_required -> forced Trash
mkdir -p "$MAC_HOME/Downloads"
dd if=/dev/zero of="$MAC_HOME/Downloads/OldApp.dmg" bs=4096 count=10 status=none
touch -d "100 days ago" "$MAC_HOME/Downloads/OldApp.dmg"

"$CLENS" scan --simulate-os macos --mode all --json > "$ROOT/mac_scan.json"
grep -q "browsers.chrome.cache" "$ROOT/mac_scan.json"
grep -q "wechat.cache.thumbnails_and_temp" "$ROOT/mac_scan.json"
grep -q "dev.cold_project_artifacts" "$ROOT/mac_scan.json"
grep -q "system.downloads_old_installers" "$ROOT/mac_scan.json"

# Dry-run MUST NOT delete anything
"$CLENS" clean --simulate-os macos --risk safe,recreatable --dry-run >/dev/null
test -f "$CHROME_BASE/data_0"
test -d "$MAC_HOME/Projects/old-app/node_modules"

# Apply Safe + Recreatable clean
"$CLENS" clean --simulate-os macos --risk safe,recreatable --apply >/dev/null

# Verify caches & stale node_modules removed, while ALL precious/active/symlink targets survived!
test ! -f "$CHROME_BASE/data_0"
test ! -f "$WECHAT_MSG/Thumb/old_thumb.jpg"
test ! -d "$MAC_HOME/Projects/old-app/node_modules"
test -f "$MAC_HOME/Desktop/important.key"
test -f "$MAC_HOME/.ssh/id_ed25519"
test -f "$WECHAT_MSG/FileStorage/File/contract.pdf"
test -f "$WECHAT_MSG/chat.db"
test -f "$MAC_HOME/Library/Application Support/Google/Chrome/Default/Cookies"
test -d "$MAC_HOME/Projects/active-app/node_modules"
test -f "$MAC_HOME/Downloads/OldApp.dmg"

# Verify review_required forced Trash routing
"$CLENS" clean --simulate-os macos --risk review_required --apply >/dev/null
test ! -f "$MAC_HOME/Downloads/OldApp.dmg"
test -f "$XDG_DATA_HOME/Trash/files/OldApp.dmg"

# Verify Space Lens & Cold File Radar
"$CLENS" lens "$LENS_DIR" --min-size-mb 0 --cold-days 0 --json > "$ROOT/lens.json"
grep -q '"skipped_cloud_placeholders": 1' "$ROOT/lens.json"
echo "PASS: Simulated macOS E2E verified."

echo "=== [3/4] Simulated Windows Filesystem E2E ==="
WIN_ROOT="$ROOT/win_env"
mkdir -p "$WIN_ROOT/Local" "$WIN_ROOT/Roaming" "$WIN_ROOT/Temp"
export HOME="$WIN_ROOT"
export USERPROFILE="$WIN_ROOT"
export LOCALAPPDATA="$WIN_ROOT/Local"
export APPDATA="$WIN_ROOT/Roaming"
export TEMP="$WIN_ROOT/Temp"
export XDG_DATA_HOME="$WIN_ROOT/.local/share"

mkdir -p "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/Cache/2026-10"
mkdir -p "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/File/2026-10"
mkdir -p "$WIN_ROOT/Local/Microsoft/Edge/User Data/Default/Cache"
mkdir -p "$WIN_ROOT/Local/D3DSCache"
dd if=/dev/zero of="$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/Cache/2026-10/thumb.dat" bs=4096 count=4 status=none
touch -d "10 days ago" "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/Cache/2026-10/thumb.dat"
echo "payroll" > "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/File/2026-10/payroll.xlsx"
dd if=/dev/zero of="$WIN_ROOT/Local/Microsoft/Edge/User Data/Default/Cache/edge.bin" bs=4096 count=4 status=none
dd if=/dev/zero of="$WIN_ROOT/Local/D3DSCache/shader.bin" bs=4096 count=4 status=none
touch -d "20 days ago" "$WIN_ROOT/Local/D3DSCache/shader.bin"

"$CLENS" scan --simulate-os windows --json > "$ROOT/win_scan.json"
grep -q "browsers.edge.cache" "$ROOT/win_scan.json"
grep -q "wechat.cache.thumbnails_and_temp" "$ROOT/win_scan.json"
grep -q "gaming.gpu.shaders" "$ROOT/win_scan.json"

"$CLENS" clean --simulate-os windows --risk safe,recreatable --apply >/dev/null
test ! -f "$WIN_ROOT/Local/Microsoft/Edge/User Data/Default/Cache/edge.bin"
test ! -f "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/Cache/2026-10/thumb.dat"
test -f "$WIN_ROOT/Documents/WeChat Files/wxid_win/FileStorage/File/2026-10/payroll.xlsx"
echo "PASS: Simulated Windows E2E verified."

echo "=== [4/4] Audit History Verification ==="
"$CLENS" audit --json > "$ROOT/audit.json"
grep -q "browsers.edge.cache" "$ROOT/audit.json"
echo "PASS: Audit JSONL trail verified."
