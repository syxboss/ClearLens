#!/usr/bin/env bash
set -euo pipefail

echo "==================================================================="
echo " ClearLens v0.1.1 — Docker Package, Clean Install & File Cleanup E2E"
echo "==================================================================="

echo ""
echo "=== [1/8] Verify Packaged .deb/.tar.gz Checksums & Clean dpkg Installation ==="
(cd /pkg && sha256sum -c SHA256SUMS)
dpkg -s clearlens-cli | grep -E "^(Package|Status|Version|Architecture):"
test "$(which clens)" = "/usr/bin/clens"
clens --version | grep -q "0.1.1"
clens rules validate
clens status | tee /tmp/clens_status.txt
grep -q "Allocator        : mimalloc" /tmp/clens_status.txt
echo "PASS: Installed /usr/bin/clens reports active mimalloc global allocator!"

echo ""
echo "=== [2/8] Seed Realistic Multi-MB Cluttered Container Filesystem ==="
LAB="/var/tmp/clearlens-lab"
rm -rf "$LAB"
export HOME="$LAB/home"
export XDG_DATA_HOME="$HOME/.local/share"
export CLEARLENS_APPS_DIR="$LAB/Applications"
mkdir -p "$HOME" "$XDG_DATA_HOME" "$CLEARLENS_APPS_DIR"

# Precious files that MUST survive 100% untouched
mkdir -p "$HOME/Desktop" "$HOME/.ssh"
echo "TOP_SECRET_KEY" > "$HOME/Desktop/never_touch.txt"
echo "SSH_PRIVATE_KEY" > "$HOME/.ssh/id_ed25519"

# 1) Chrome Cache (2 MB) + symlink trap + precious Cookies
CHROME_CACHE="$HOME/Library/Caches/Google/Chrome/Default/Cache"
mkdir -p "$CHROME_CACHE" "$HOME/Library/Application Support/Google/Chrome/Default"
dd if=/dev/urandom of="$CHROME_CACHE/cache_blob.bin" bs=1048576 count=2 status=none
ln -s "$HOME/Desktop" "$CHROME_CACHE/desktop_symlink_trap"
echo "CHROME_SESSION_COOKIE" > "$HOME/Library/Application Support/Google/Chrome/Default/Cookies"

# 2) WeChat Thumb/Cache (2 MB) vs WeChat Documents & DB (MUST KEEP)
WECHAT_BASE="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Library"
mkdir -p "$WECHAT_BASE/Caches/tmp" "$WECHAT_BASE/Application Support/com.tencent.xinWeChat/2.0/u1/Message/MessageTemp/c1/FileStorage/File"
dd if=/dev/urandom of="$WECHAT_BASE/Caches/tmp/img_cache.bin" bs=1048576 count=2 status=none
touch -d "10 days ago" "$WECHAT_BASE/Caches/tmp/img_cache.bin"
echo "CONTRACT_PDF" > "$WECHAT_BASE/Application Support/com.tencent.xinWeChat/2.0/u1/Message/MessageTemp/c1/FileStorage/File/contract.pdf"
echo "WECHAT_DB" > "$WECHAT_BASE/Application Support/com.tencent.xinWeChat/2.0/u1/Message/MessageTemp/c1/chat.db"

# 3) Custom Developer Workspace (P0.4 config add-workspace) — Cold (4 MB) vs Active (2 MB)
CUSTOM_WS="$LAB/CustomWorkspace"
mkdir -p "$CUSTOM_WS/legacy-portal/node_modules/pkg" "$CUSTOM_WS/live-api/node_modules/pkg"
echo '{"name":"legacy"}' > "$CUSTOM_WS/legacy-portal/package.json"
dd if=/dev/urandom of="$CUSTOM_WS/legacy-portal/node_modules/pkg/bundle.js" bs=1048576 count=4 status=none
touch -d "45 days ago" "$CUSTOM_WS/legacy-portal/package.json" "$CUSTOM_WS/legacy-portal"
echo '{"name":"live"}' > "$CUSTOM_WS/live-api/package.json"
dd if=/dev/urandom of="$CUSTOM_WS/live-api/node_modules/pkg/bundle.js" bs=1048576 count=2 status=none

# 4) Ollama Models with Shared Base Layer (P0.1 RefCount Blob GC)
OLLAMA_MODELS="$HOME/.ollama/models"
mkdir -p "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-old" \
         "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-keep" \
         "$OLLAMA_MODELS/blobs"
dd if=/dev/urandom of="$OLLAMA_MODELS/blobs/sha256-sharedbase" bs=1048576 count=3 status=none
dd if=/dev/urandom of="$OLLAMA_MODELS/blobs/sha256-oldweights" bs=1048576 count=5 status=none
dd if=/dev/urandom of="$OLLAMA_MODELS/blobs/sha256-keepweights" bs=1048576 count=4 status=none
cat > "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-old/latest" << 'EOF'
{"layers":[{"digest":"sha256:sharedbase"},{"digest":"sha256:oldweights"}]}
EOF
cat > "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-keep/latest" << 'EOF'
{"layers":[{"digest":"sha256:sharedbase"},{"digest":"sha256:keepweights"}]}
EOF

# 5) Duplicate Files (P1.1 BLAKE3 3-stage funnel + Hardlink skip + Distinct middle byte)
mkdir -p "$HOME/MediaArchive" "$HOME/Downloads"
dd if=/dev/urandom of="$HOME/MediaArchive/master_clip.mp4" bs=1048576 count=2 status=none
cp "$HOME/MediaArchive/master_clip.mp4" "$HOME/Downloads/master_clip_copy1.mp4"
cp "$HOME/MediaArchive/master_clip.mp4" "$HOME/Downloads/master_clip_copy2.mp4"
ln "$HOME/MediaArchive/master_clip.mp4" "$HOME/MediaArchive/master_clip_hardlink.mp4"
cp "$HOME/MediaArchive/master_clip.mp4" "$HOME/MediaArchive/same_size_distinct.mp4"
printf '\xAA\xBB\xCC\xDD' | dd of="$HOME/MediaArchive/same_size_distinct.mp4" bs=1 seek=1000000 conv=notrunc status=none

# 6) Installed App vs Stale Orphan Residue (P1.2 Uninstaller & Orphan Hunter)
mkdir -p "$CLEARLENS_APPS_DIR/KeepNotes.app/Contents"
cat > "$CLEARLENS_APPS_DIR/KeepNotes.app/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.keepnotes</string>
  <key>CFBundleName</key><string>KeepNotes</string>
</dict></plist>
EOF
dd if=/dev/urandom of="$CLEARLENS_APPS_DIR/KeepNotes.app/Contents/bin" bs=1048576 count=1 status=none
mkdir -p "$HOME/Library/Caches/com.example.keepnotes" "$HOME/Library/Caches/com.apple.Safari"
dd if=/dev/urandom of="$HOME/Library/Caches/com.example.keepnotes/idx.dat" bs=1048576 count=1 status=none
dd if=/dev/urandom of="$HOME/Library/Caches/com.apple.Safari/ok.dat" bs=1048576 count=1 status=none

ORPHAN_DIR="$HOME/Library/Application Support/com.ghost.oldapp"
mkdir -p "$ORPHAN_DIR"
dd if=/dev/urandom of="$ORPHAN_DIR/ghost_data.bin" bs=1048576 count=3 status=none
touch -d "40 days ago" "$ORPHAN_DIR/ghost_data.bin" "$ORPHAN_DIR"

# 7) Stale .dmg in Downloads (100d old, 2 MB -> review_required -> Trash)
dd if=/dev/urandom of="$HOME/Downloads/LegacyTool.dmg" bs=1048576 count=2 status=none
touch -d "100 days ago" "$HOME/Downloads/LegacyTool.dmg"

# 8) Sparse Virtual Disk Image (Docker.raw: 64 KB physical data, 16 MB logical ceiling -> NEVER deleted)
DOCKER_VM_DIR="$HOME/Library/Containers/com.docker.docker/Data/vms/0/data"
mkdir -p "$DOCKER_VM_DIR"
dd if=/dev/urandom of="$DOCKER_VM_DIR/Docker.raw" bs=1024 count=64 status=none
truncate -s 16M "$DOCKER_VM_DIR/Docker.raw"

BEFORE_KB=$(du -sk "$LAB" | awk '{print $1}')
echo "Container Lab Footprint BEFORE Cleanup: ${BEFORE_KB} KB (~$((BEFORE_KB / 1024)) MB)"

echo ""
echo "=== [3/8] Configure Custom Workspace & Run P0 Smart + Deep Clean Inside Container ==="
clens config add-workspace "$CUSTOM_WS"
clens scan --simulate-os macos --mode all --json > /tmp/pkg_scan.json
grep -q "browsers.chrome.cache" /tmp/pkg_scan.json
grep -q "wechat.cache.thumbnails_and_temp" /tmp/pkg_scan.json
grep -q "dev.cold_project_artifacts" /tmp/pkg_scan.json
grep -q "ai.ollama_models" /tmp/pkg_scan.json

# Dry-run MUST NOT mutate any files
clens clean --simulate-os macos --risk safe,recreatable --dry-run
test -f "$CHROME_CACHE/cache_blob.bin"
test -d "$CUSTOM_WS/legacy-portal/node_modules"

# Real permanent cleanup of Safe + Recreatable items inside container
clens clean --simulate-os macos --risk safe,recreatable --apply
test ! -f "$CHROME_CACHE/cache_blob.bin"
test ! -f "$WECHAT_BASE/Caches/tmp/img_cache.bin"
test ! -d "$CUSTOM_WS/legacy-portal/node_modules"
# Active project & precious files MUST remain intact
test -d "$CUSTOM_WS/live-api/node_modules"
test -f "$HOME/Desktop/never_touch.txt"
test -f "$HOME/.ssh/id_ed25519"
test -f "$HOME/Library/Application Support/Google/Chrome/Default/Cookies"
test -f "$WECHAT_BASE/Application Support/com.tencent.xinWeChat/2.0/u1/Message/MessageTemp/c1/FileStorage/File/contract.pdf"
test -f "$WECHAT_BASE/Application Support/com.tencent.xinWeChat/2.0/u1/Message/MessageTemp/c1/chat.db"

echo ""
echo "=== [4/8] Verify P0.1 Ollama RefCount Blob GC Inside Container ==="
clens clean --simulate-os macos --risk review_required --rule ai.ollama_models --match-path llama-old --apply
test ! -f "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-old/latest"
test ! -f "$OLLAMA_MODELS/blobs/sha256-oldweights"
test -f "$OLLAMA_MODELS/blobs/sha256-sharedbase"
test -f "$OLLAMA_MODELS/blobs/sha256-keepweights"
test -f "$OLLAMA_MODELS/manifests/registry.ollama.ai/library/llama-keep/latest"
test -f "$XDG_DATA_HOME/Trash/files/sha256-oldweights"
echo "PASS: Ollama exclusive 5MB blob moved to Trash; 3MB shared base layer preserved!"

echo ""
echo "=== [5/8] Verify P1.1 BLAKE3 Duplicate Detection & Safe Cleanup Inside Container ==="
clens duplicates "$HOME" --min-size-kb 1024 --json > /tmp/pkg_dups.json
grep -q '"skipped_hardlinks": 1' /tmp/pkg_dups.json
clens duplicates-clean "$HOME" --min-size-kb 1024 --apply
test -f "$HOME/MediaArchive/master_clip.mp4"
test -f "$HOME/MediaArchive/same_size_distinct.mp4"
test ! -f "$HOME/Downloads/master_clip_copy1.mp4"
test ! -f "$HOME/Downloads/master_clip_copy2.mp4"
test -f "$XDG_DATA_HOME/Trash/files/master_clip_copy1.mp4"
test -f "$XDG_DATA_HOME/Trash/files/master_clip_copy2.mp4"
echo "PASS: 2 duplicate copies moved to Trash; original, hardlink, and distinct same-size file kept!"

echo ""
echo "=== [6/8] Verify P1.2 App Uninstaller & Orphan Residue Hunter Inside Container ==="
clens apps --simulate-os macos
clens orphans --simulate-os macos --min-age-days 14 --apply
test ! -d "$ORPHAN_DIR"
test -d "$HOME/Library/Caches/com.example.keepnotes"
test -d "$HOME/Library/Caches/com.apple.Safari"
test -d "$XDG_DATA_HOME/Trash/files/com.ghost.oldapp"
echo "PASS: Orphan com.ghost.oldapp moved to Trash; KeepNotes & com.apple.Safari untouched!"

echo ""
echo "=== [6.5/8] Verify Virtual Disk Compaction Inspector (Read-Only, Zero Deletion) ==="
clens vdisks --simulate-os macos --show-script | tee /tmp/pkg_vdisks.txt
grep -q "Docker Desktop (Docker.raw)" /tmp/pkg_vdisks.txt
grep -q "docker builder prune" /tmp/pkg_vdisks.txt
test -f "$DOCKER_VM_DIR/Docker.raw"
echo "PASS: Sparse Docker.raw inspected safely with compaction script and zero file deletion!"

echo ""
echo "=== [7/8] Measure Container Disk Reclamation & Inspect Audit Trail ==="
# Active workspace footprint excluding Trash vs total including Trash
ACTIVE_AFTER_KB=$(du -sk --exclude="$XDG_DATA_HOME/Trash" "$LAB" | awk '{print $1}')
TRASH_KB=$(du -sk "$XDG_DATA_HOME/Trash" | awk '{print $1}')
PERMANENTLY_FREED_KB=$((BEFORE_KB - ACTIVE_AFTER_KB - TRASH_KB))
TOTAL_RECLAIMED_FROM_ACTIVE_KB=$((BEFORE_KB - ACTIVE_AFTER_KB))
echo "BEFORE Active Footprint : ${BEFORE_KB} KB (~$((BEFORE_KB / 1024)) MB)"
echo "AFTER  Active Footprint : ${ACTIVE_AFTER_KB} KB (~$((ACTIVE_AFTER_KB / 1024)) MB)"
echo "Reclaimed Immediately   : ${PERMANENTLY_FREED_KB} KB (~$((PERMANENTLY_FREED_KB / 1024)) MB permanently freed)"
echo "Safely Routed to Trash  : ${TRASH_KB} KB (~$((TRASH_KB / 1024)) MB recoverable in OS Trash)"
echo "Total Cleaned from Lab  : ${TOTAL_RECLAIMED_FROM_ACTIVE_KB} KB (~$((TOTAL_RECLAIMED_FROM_ACTIVE_KB / 1024)) MB)"
test "$TOTAL_RECLAIMED_FROM_ACTIVE_KB" -ge 18000

echo ""
echo "Audit Log Summary:"
clens audit --limit 20

echo ""
echo "=== [8/8] Verify Clean Package Removal & Reinstall Lifecycle ==="
dpkg -r clearlens-cli >/dev/null
test ! -f /usr/bin/clens
dpkg -i /pkg/clearlens-cli_0.1.1_*.deb >/dev/null
test -x /usr/bin/clens
echo "PASS: .deb install -> real container cleanup -> remove -> reinstall verified!"
