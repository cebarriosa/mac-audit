#!/bin/bash
#
# mac-audit.sh - disk, users, caches, security and network triage for macOS.
# Only uses what ships with macOS (bash 3.2, no Homebrew, no Python).
# Changes nothing on the Mac unless you pass --clean.
#
# Usage:  sudo ./mac-audit.sh [--clean] [--days N] [--no-lan-scan] [--output DIR]

set -u
umask 077

readonly SECONDS_PER_DAY=86400
readonly APPLE_EPOCH_OFFSET=978307200
readonly DISK_WARN_PERCENT=80
readonly DISK_ALERT_PERCENT=90
readonly MAX_SCAN_PREFIX=22
readonly FALLBACK_SCAN_MASK=0xffffff00
readonly PING_BATCH_SIZE=64
readonly SOFTWAREUPDATE_TIMEOUT=90
readonly BONJOUR_TIMEOUT=6
readonly SCREENLOCK_TIMEOUT=5
readonly TOP_N=15
readonly QUARANTINE_SCREEN_ROWS=40
readonly MAX_LIST_ITEMS=30
readonly MAX_TEXT=200

readonly RISKY_EXTENSIONS='\.(dmg|pkg|mpkg|app|zip|7z|rar|tgz|gz|iso|img|command|tool|sh|scpt|applescript|jar|js|html?|svg|docm|xlsm|pptm|terminal|webloc|inetloc|fileloc)$'
readonly SUSPICIOUS_SHELL_PATTERNS='curl |wget |base64|osascript|nc |/dev/tcp|/tmp/|python[0-9.]* -c|bash -i'
readonly WELL_KNOWN_DNS='1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220'
readonly BONJOUR_TYPES='_device-info._tcp _companion-link._tcp _airplay._tcp _raop._tcp _smb._tcp _afpovertcp._tcp _ssh._tcp _sftp-ssh._tcp _rfb._tcp _ipp._tcp _printer._tcp _pdl-datastream._tcp _googlecast._tcp _hap._tcp _http._tcp'
readonly REMOTE_ACCESS_PORTS='22|Remote Login (SSH)
5900|Screen Sharing / VNC
3283|Apple Remote Desktop
445|File Sharing (SMB)
548|File Sharing (AFP)
3389|Remote Desktop (RDP)'
readonly CHROMIUM_BROWSERS='Google/Chrome|Chrome
Microsoft Edge|Edge
BraveSoftware/Brave-Browser|Brave
Vivaldi|Vivaldi
Arc/User Data|Arc
Chromium|Chromium'

RECENT_DAYS=30
DO_CLEAN=0
DO_LAN_SCAN=1
OUTPUT_PARENT="$PWD"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Health and security audit for macOS. Read-only unless --clean is given.

Options:
  --clean          after the audit, offer to delete safe-to-remove caches (asks before each one)
  --days N         how many days back counts as "recent" (default: $RECENT_DAYS)
  --no-lan-scan    skip discovering other devices on the local network
  --output DIR     where to write the report folder (default: current directory)
  -h, --help       show this help

Run with sudo for the full picture:  sudo $0
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --clean) DO_CLEAN=1 ;;
    --no-lan-scan) DO_LAN_SCAN=0 ;;
    --days) shift; RECENT_DAYS=${1:-} ;;
    --output) shift; OUTPUT_PARENT=${1:-} ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$RECENT_DAYS" in ''|*[!0-9]*) echo "--days needs a whole number" >&2; exit 2 ;; esac
[ "$(uname -s)" = "Darwin" ] || { echo "This script only runs on macOS." >&2; exit 1; }
[ -n "$OUTPUT_PARENT" ] && [ -d "$OUTPUT_PARENT" ] || { echo "Output folder not found: $OUTPUT_PARENT" >&2; exit 2; }

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
INVOKING_USER=${SUDO_USER:-$(id -un)}
NOW=$(date +%s)
RECENT_CUTOFF=$((NOW - RECENT_DAYS * SECONDS_PER_DAY))
HOST_NAME=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
REPORT_DIR="$OUTPUT_PARENT/mac-audit-$HOST_NAME-$(date +%Y%m%d-%H%M%S)"
REPORT="$REPORT_DIR/report.txt"
mkdir -p "$REPORT_DIR" || { echo "Can't create $REPORT_DIR" >&2; exit 1; }
: > "$REPORT"

WORK_DIR=$(mktemp -d -t mac-audit) || exit 1
trap 'rm -rf "$WORK_DIR"' EXIT
FINDINGS="$WORK_DIR/findings"
CLEAN_CANDIDATES="$WORK_DIR/clean_candidates"
HOMES_FILE="$WORK_DIR/homes"
HWPORTS_FILE="$WORK_DIR/hwports"
JSON_HELPER="$WORK_DIR/json_helper.js"
: > "$FINDINGS"
: > "$CLEAN_CANDIDATES"
CURRENT_SECTION="-"

if [ -t 1 ]; then
  RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; BLUE=$'\033[34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; BLUE=''; BOLD=''; RESET=''
fi

# ---------------------------------------------------------------- output

to_both() { printf '%s\n' "$1"; printf '%s\n' "$2" >> "$REPORT"; }
section() { CURRENT_SECTION=$1; to_both "" ""; to_both "${BOLD}${BLUE}==== $1 ====${RESET}" "==== $1 ===="; }
subsection() { to_both "${BOLD}-- $1${RESET}" "-- $1"; }
info() { to_both "    $1" "    $1"; }
ok() { to_both "  ${GREEN}[OK]${RESET}    $1" "  [OK]    $1"; }
skip() { to_both "  [SKIP]  $1" "  [SKIP]  $1"; }
warn() { to_both "  ${YELLOW}[WARN]${RESET}  $1" "  [WARN]  $1"; echo "WARN|$CURRENT_SECTION|$1" >> "$FINDINGS"; }
alert() { to_both "  ${RED}[ALERT]${RESET} $1" "  [ALERT] $1"; echo "ALERT|$CURRENT_SECTION|$1" >> "$FINDINGS"; }
indent() { sed 's/^/      /' | tee -a "$REPORT"; }

report_level() {
  case "$1" in
    2) alert "$2" ;;
    1) warn "$2" ;;
    *) info "$2" ;;
  esac
}

# ---------------------------------------------------------------- helpers

human_kb() {
  awk -v k="${1:-0}" 'BEGIN { split("KB MB GB TB", u); i = 1; while (k >= 1024 && i < 4) { k /= 1024; i++ } printf "%.1f %s", k, u[i] }'
}

size_kb() {
  local kb
  kb=$(du -skx "$1" 2>/dev/null | awk '{print $1}')
  echo "${kb:-0}"
}

mtime_of() { stat -f %m "$1" 2>/dev/null || echo 0; }
fmt_date() { date -r "$1" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "?"; }
is_recent() { [ "$(mtime_of "$1")" -ge "$RECENT_CUTOFF" ]; }
plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }
shorten() { local text=$1; [ ${#text} -gt $MAX_TEXT ] && text="${text:0:$MAX_TEXT}..."; printf '%s' "$text"; }

dscl_value() {
  dscl . -read "/Users/$1" "$2" 2>/dev/null | sed "s/^$2://" | tr '\n' ' ' | sed 's/^ *//; s/ *$//'
}

as_user() {
  local user=$1; shift
  if [ "$IS_ROOT" -eq 1 ] && [ "$user" != "root" ]; then sudo -u "$user" "$@"; else "$@"; fi
}

run_with_timeout() {
  local seconds=$1; shift
  "$@" &
  local pid=$!
  ( sleep "$seconds"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local watcher=$!
  wait "$pid" 2>/dev/null
  local status=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  return $status
}

# prints: apple | signed:<authority> | adhoc | unsigned | invalid:<authority> | missing | unreadable | unknown
signature_of() {
  local target=$1 details authority
  [ -e "$target" ] || { echo missing; return; }
  [ -r "$target" ] || { echo unreadable; return; }
  details=$(codesign -dv --verbose=2 "$target" 2>&1)
  case "$details" in
    *"not signed at all"*) echo unsigned; return ;;
    *"Signature=adhoc"*) echo adhoc; return ;;
  esac
  authority=$(printf '%s\n' "$details" | sed -n 's/^Authority=//p' | head -1)
  if [ "${2:-}" = "verify" ] && ! codesign --verify "$target" >/dev/null 2>&1; then
    echo "invalid:$authority"; return
  fi
  case "$authority" in
    "Software Signing") echo apple ;;
    "") echo unknown ;;
    *) echo "signed:$authority" ;;
  esac
}

is_interpreter() {
  case "$(basename "$1")" in
    sh|bash|zsh|dash|ksh|csh|tcsh|osascript|curl|wget|nc|node|perl*|ruby*|python*) return 0 ;;
  esac
  return 1
}

is_temp_location() {
  case "$1" in
    /tmp/*|/private/tmp/*|/private/var/tmp/*|/Users/Shared/*) return 0 ;;
  esac
  return 1
}

ip_to_int() {
  local IFS=.
  set -- $1
  echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
}

int_to_ip() {
  echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"
}

prefix_of_mask() {
  local mask=$1 bits=0
  while [ $mask -gt 0 ]; do bits=$((bits + (mask & 1))); mask=$((mask >> 1)); done
  echo $bits
}

list_local_users() {
  dscl . -list /Users UniqueID 2>/dev/null | while read -r name uid; do
    case "$name" in _*|root|daemon|nobody) continue ;; esac
    [ "$uid" -ge 500 ] 2>/dev/null || continue
    echo "$name|$uid|$(dscl_value "$name" NFSHomeDirectory)"
  done
}

collect_target_homes() {
  if [ "$IS_ROOT" -eq 1 ]; then
    list_local_users | while IFS='|' read -r name _ home; do
      [ -d "$home" ] && echo "$name|$home"
    done > "$HOMES_FILE"
  else
    echo "$(id -un)|$HOME" > "$HOMES_FILE"
  fi
}

detect_full_disk_access() {
  local probe
  if [ "$IS_ROOT" -eq 1 ]; then
    probe="/Library/Application Support/com.apple.TCC/TCC.db"
  else
    probe="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  fi
  sqlite3 "$probe" "select 1;" >/dev/null 2>&1
}

copy_sqlite() {
  local source=$1 target=$2 suffix
  cp "$source" "$target" 2>/dev/null || return 1
  for suffix in -wal -shm; do
    [ -f "$source$suffix" ] && cp "$source$suffix" "$target$suffix" 2>/dev/null
  done
  return 0
}

write_json_helper() {
  cat > "$JSON_HELPER" <<'EOF'
ObjC.import('Foundation');

function readText(path) {
  var text = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
  return text.isNil() ? null : text.js;
}

function parseFile(path) {
  try { return JSON.parse(readText(path)); } catch (e) { return null; }
}

function localizedName(dir, manifest) {
  var name = manifest.name || '?';
  var match = /^__MSG_(.+)__$/.exec(name);
  if (!match) return name;
  var locales = [manifest.default_locale, 'en', 'en_US'];
  for (var i = 0; i < locales.length; i++) {
    if (!locales[i]) continue;
    var messages = parseFile(dir + '/_locales/' + locales[i] + '/messages.json');
    if (!messages) continue;
    for (var key in messages) {
      if (key.toLowerCase() === match[1].toLowerCase() && messages[key].message) return messages[key].message;
    }
  }
  return name;
}

function hasAllSitesAccess(manifest) {
  var patterns = [].concat(manifest.permissions || [], manifest.host_permissions || []);
  (manifest.content_scripts || []).forEach(function (script) { patterns = patterns.concat(script.matches || []); });
  return patterns.some(function (p) { return p === '<all_urls>' || /^(\*|https?):\/\/\*\/\*$/.test(p); });
}

function chromium(dir) {
  var manifest = parseFile(dir + '/manifest.json');
  if (!manifest) return '?|?|';
  return [localizedName(dir, manifest), manifest.version || '?', hasAllSitesAccess(manifest) ? 'all-sites' : ''].join('|');
}

function firefox(path) {
  var data = parseFile(path);
  if (!data || !data.addons) return '';
  return data.addons
    .filter(function (a) { return a.type === 'extension' && a.location === 'app-profile'; })
    .map(function (a) { return [(a.defaultLocale && a.defaultLocale.name) || a.id, a.version || '?', a.active ? 'enabled' : 'disabled'].join('|'); })
    .join('\n');
}

function run(argv) {
  return argv[0] === 'firefox' ? firefox(argv[1]) : chromium(argv[1]);
}
EOF
}

json_helper() { osascript -l JavaScript "$JSON_HELPER" "$@" 2>/dev/null; }

# ---------------------------------------------------------------- 1. system

check_system() {
  section "1. System"
  info "Computer name : $(scutil --get ComputerName 2>/dev/null)"
  info "macOS         : $(sw_vers -productName) $(sw_vers -productVersion) (build $(sw_vers -buildVersion))"
  info "Hardware      : $(sysctl -n hw.model 2>/dev/null) / $(uname -m)"
  info "Uptime        : $(uptime | sed 's/^ *//')"

  local xprotect_version
  xprotect_version=$(xprotect version 2>/dev/null | head -1)
  [ -n "$xprotect_version" ] || xprotect_version=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null)
  info "XProtect      : ${xprotect_version:-unknown}"

  subsection "Pending software updates (needs internet, up to ${SOFTWAREUPDATE_TIMEOUT}s)"
  local updates
  updates=$(run_with_timeout "$SOFTWAREUPDATE_TIMEOUT" softwareupdate -l 2>&1)
  if printf '%s' "$updates" | grep -q "No new software available"; then
    ok "macOS is up to date"
  elif printf '%s' "$updates" | grep -q '^\* Label:'; then
    printf '%s\n' "$updates" | sed -n 's/^\* Label: //p' | while read -r label; do
      warn "Update pending: $label (install it: System Settings > General > Software Update)"
    done
  else
    info "Could not check for updates (offline or timed out)"
  fi

  subsection "Last installed updates"
  softwareupdate --history 2>/dev/null | head -8 | indent
}

# ---------------------------------------------------------------- 2. disk

list_largest_folders() {
  du -kxd 1 "$1" 2>/dev/null | sort -rn | sed 1d | head -n "$TOP_N" | while read -r kb path; do
    info "$(printf '%10s  %s' "$(human_kb "$kb")" "$path")"
  done
}

check_disk() {
  section "2. Disk space"
  df -hl 2>/dev/null | grep -vE '^(devfs|map )' | indent

  local volume=/System/Volumes/Data used_percent free_kb snapshots
  [ -d "$volume" ] || volume=/
  used_percent=$(df -Pk "$volume" | awk 'NR==2 { gsub("%", "", $5); print $5 }')
  free_kb=$(df -Pk "$volume" | awk 'NR==2 { print $4 }')
  if [ "$used_percent" -ge "$DISK_ALERT_PERCENT" ]; then
    alert "Disk is ${used_percent}% full, only $(human_kb "$free_kb") free"
  elif [ "$used_percent" -ge "$DISK_WARN_PERCENT" ]; then
    warn "Disk is ${used_percent}% full, $(human_kb "$free_kb") free"
  else
    ok "Disk is ${used_percent}% full, $(human_kb "$free_kb") free"
  fi

  snapshots=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c 'com.apple')
  [ "$snapshots" -gt 0 ] && info "$snapshots local Time Machine snapshot(s); macOS deletes them on its own when space runs low"

  local user home
  while IFS='|' read -r user home <&3; do
    subsection "Largest folders in $home (can take a few minutes)"
    list_largest_folders "$home"
    subsection "Largest folders in $home/Library"
    list_largest_folders "$home/Library"
  done 3< "$HOMES_FILE"
}

# ---------------------------------------------------------------- 3. caches

user_cache_items() {
  cat <<'EOF'
Library/Caches|SAFE|app caches, rebuilt automatically (includes browser caches)
Library/Developer/Xcode/DerivedData|SAFE|Xcode build files
Library/Developer/Xcode/iOS DeviceSupport|SAFE|Xcode device symbols, downloaded again when needed
Library/Developer/CoreSimulator/Caches|SAFE|iOS simulator caches
.npm/_cacache|SAFE|npm package cache
.gradle/caches|SAFE|Gradle cache
.m2/repository|SAFE|Maven downloads, downloaded again on the next build
.cache|SAFE|command-line tool caches
Library/Logs|REVIEW|app logs, useful evidence after an incident
.Trash|REVIEW|Trash, check nothing is needed before emptying
Downloads|REVIEW|Downloads, look for the phishing attachment first
Library/Containers/com.apple.mail/Data/Library/Mail Downloads|REVIEW|attachments opened from Mail, evidence of the phishing email
Library/Application Support/MobileSync/Backup|REVIEW|iPhone/iPad backups
Library/Developer/Xcode/Archives|REVIEW|Xcode app archives
Library/Developer/CoreSimulator/Devices|REVIEW|iOS simulators, remove them from Xcode instead
Library/Containers/com.docker.docker|REVIEW|Docker images and volumes, clean with: docker system prune
EOF
}

system_cache_items() {
  cat <<'EOF'
/Library/Caches|REVIEW|system-wide caches, mostly safe but leave them unless space is critical
/Library/Logs|REVIEW|system logs, evidence after an incident
/private/var/log|REVIEW|system logs, evidence after an incident
/Library/Updates|REVIEW|downloaded macOS updates
/private/var/vm|NEVER|swap and sleep image, managed by macOS
/private/var/folders|NEVER|per-user temporary files, managed by macOS
EOF
}

report_cache_item() {
  local home=$1 path=$2 kind=$3 description=$4 kb
  [ -e "$path" ] || return 0
  kb=$(size_kb "$path")
  [ "$kb" -gt 0 ] || return 0
  info "$(printf '%-7s %10s  %s  (%s)' "$kind" "$(human_kb "$kb")" "$path" "$description")"
  [ "$kind" = "SAFE" ] && echo "$kb|$home|$path|$description" >> "$CLEAN_CANDIDATES"
  return 0
}

check_caches() {
  section "3. Caches and removable files"
  info "SAFE   = can be deleted, apps rebuild it (use --clean)"
  info "REVIEW = look at it first, it may hold data or evidence"
  info "NEVER  = managed by macOS, do not touch"

  local user home relative kind description
  while IFS='|' read -r user home <&3; do
    subsection "User $user"
    while IFS='|' read -r relative kind description <&4; do
      report_cache_item "$home" "$home/$relative" "$kind" "$description"
    done 4< <(user_cache_items)

    if [ -d "$home/Library/Caches" ]; then
      info "Biggest entries inside $home/Library/Caches:"
      du -skx "$home/Library/Caches"/* 2>/dev/null | sort -rn | head -n 10 | while read -r kb path; do
        info "$(printf '          %10s  %s' "$(human_kb "$kb")" "$(basename "$path")")"
      done
    fi
  done 3< "$HOMES_FILE"

  subsection "System"
  while IFS='|' read -r relative kind description <&4; do
    report_cache_item "" "$relative" "$kind" "$description"
  done 4< <(system_cache_items)

  local total_kb
  total_kb=$(awk -F'|' '{ s += $1 } END { print s + 0 }' "$CLEAN_CANDIDATES")
  info ""
  info "About $(human_kb "$total_kb") can be freed with --clean"
}

# ---------------------------------------------------------------- 4. users

account_creation_epoch() {
  local policy="$WORK_DIR/policy.plist" created
  dscl . -read "/Users/$1" accountPolicyData 2>/dev/null | sed 1d > "$policy"
  created=$(plist_value "$policy" creationTime)
  echo "${created%%.*}"
}

check_ssh_keys() {
  local user home keys
  while IFS='|' read -r user home <&3; do
    keys="$home/.ssh/authorized_keys"
    [ -s "$keys" ] || continue
    warn "$user has SSH keys that allow logging in remotely: $keys ($(grep -cvE '^[[:space:]]*(#|$)' "$keys") key(s)). Remove any you don't recognize"
    awk '!/^[[:space:]]*(#|$)/ { print "key comment: " $NF }' "$keys" | indent
  done 3< "$HOMES_FILE"
}

check_sudoers() {
  if [ "$IS_ROOT" -ne 1 ]; then
    skip "sudoers check needs sudo"
    return
  fi
  local custom
  custom=$(grep -vE '^[[:space:]]*(#|$|Defaults|root[[:space:]]|%admin[[:space:]])' /etc/sudoers 2>/dev/null)
  if [ -n "$custom" ]; then
    warn "Extra rules in /etc/sudoers"
    printf '%s\n' "$custom" | indent
  else
    ok "/etc/sudoers has only the default rules"
  fi
  grep -q NOPASSWD /etc/sudoers 2>/dev/null && warn "/etc/sudoers lets someone run admin commands without a password (NOPASSWD)"
  local file
  for file in /etc/sudoers.d/*; do
    [ -f "$file" ] || continue
    warn "Extra sudo rules file: $file"
    indent < "$file"
  done
}

check_users() {
  section "4. User accounts"

  local extra_root admins
  extra_root=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 == 0 && $1 != "root" { print $1 }')
  if [ -n "$extra_root" ]; then
    alert "Accounts with the root UID 0 besides root: $extra_root"
  else
    ok "Only 'root' has UID 0"
  fi
  admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: //')
  info "Admin group members: ${admins:-none}"

  subsection "Local accounts"
  local name uid home real_name shell is_admin created flags level
  list_local_users | while IFS='|' read -r name uid home; do
    real_name=$(dscl_value "$name" RealName)
    shell=$(dscl_value "$name" UserShell)
    is_admin=no
    dsmemberutil checkmembership -U "$name" -G admin 2>/dev/null | grep -q "is a member" && is_admin=yes
    created=$(account_creation_epoch "$name")
    flags=""
    level=0
    case "$(dscl_value "$name" IsHidden)" in 1|yes|YES|true) flags="$flags hidden account;"; level=1 ;; esac
    if [ -n "$created" ] && [ "$created" -ge "$RECENT_CUTOFF" ] 2>/dev/null; then
      flags="$flags created $(fmt_date "$created");"
      level=1
    fi
    [ "$uid" -lt 501 ] && { flags="$flags unusual UID;"; level=1; }
    report_level "$level" "$name (uid $uid, \"$real_name\") admin=$is_admin home=$home shell=$shell${flags:+ ->$flags}"
  done

  [ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" = "1" ] \
    && warn "Guest account is on" || ok "Guest account is off"
  local auto_login
  auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
  [ -n "$auto_login" ] && warn "Automatic login is on for '$auto_login' (anyone with the Mac gets in)" || ok "Automatic login is off"

  subsection "Recent logins"
  last -15 2>/dev/null | indent

  subsection "Remote login keys and sudo rules"
  check_ssh_keys
  check_sudoers
}

# ---------------------------------------------------------------- 5. security settings

check_listening_service() {
  local listening=$1 port name
  while IFS='|' read -r port name; do
    if printf '%s\n' "$listening" | grep -qx "$port"; then
      warn "$name is ON (port $port). Turn it off in System Settings > General > Sharing unless you need it"
    fi
  done <<EOF
$REMOTE_ACCESS_PORTS
EOF
}

check_update_settings() {
  local prefs=/Library/Preferences/com.apple.SoftwareUpdate
  [ "$(defaults read $prefs AutomaticCheckEnabled 2>/dev/null)" = "0" ] && warn "Automatic update checks are off"
  [ "$(defaults read $prefs CriticalUpdateInstall 2>/dev/null)" = "0" ] && warn "Security responses / system files are not installed automatically"
  [ "$(defaults read $prefs ConfigDataInstall 2>/dev/null)" = "0" ] && warn "XProtect malware definitions are not updated automatically"
  return 0
}

check_security_settings() {
  section "5. Security settings"

  csrutil status 2>/dev/null | grep -q "enabled" \
    && ok "System Integrity Protection is on" \
    || alert "System Integrity Protection is OFF"
  spctl --status 2>/dev/null | grep -q "assessments enabled" \
    && ok "Gatekeeper is on" \
    || alert "Gatekeeper is OFF (any app can run without checks)"
  fdesetup status 2>/dev/null | grep -q "FileVault is On" \
    && ok "FileVault disk encryption is on" \
    || warn "FileVault is off (data readable if the Mac is stolen)"

  local firewall=/usr/libexec/ApplicationFirewall/socketfilterfw
  "$firewall" --getglobalstate 2>/dev/null | grep -qi "enabled" \
    && ok "Firewall is on" \
    || warn "Firewall is off (System Settings > Network > Firewall)"
  "$firewall" --getstealthmode 2>/dev/null | grep -qiE 'stealth mode (is )?(on|enabled)' \
    && ok "Firewall stealth mode is on" \
    || info "Firewall stealth mode is off"

  check_update_settings

  local screen_lock
  screen_lock=$(run_with_timeout "$SCREENLOCK_TIMEOUT" sysadminctl -screenLock status 2>&1 </dev/null)
  case "$screen_lock" in
    *"is off"*) warn "Password after sleep / screen saver is off" ;;
    *screenLock*) ok "Password after sleep: $(printf '%s' "$screen_lock" | sed -n 's/.*screenLock //p' | head -1)" ;;
  esac

  subsection "Remote access and sharing services"
  local listening
  listening=$(netstat -an -p tcp 2>/dev/null | awk '/LISTEN/ { print $4 }' | sed 's/.*\.//' | sort -u)
  check_listening_service "$listening"
  ok "Checked remote access ports: 22, 5900, 3283, 445, 548, 3389"
}

# ---------------------------------------------------------------- 6. persistence / tampering

check_launch_plist() {
  local plist=$1 name program arguments signature signer="-" reasons="" level=0
  name=$(basename "$plist")
  program=$(plist_value "$plist" Program)
  [ -n "$program" ] || program=$(plist_value "$plist" ProgramArguments:0)
  arguments=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments" "$plist" 2>/dev/null | sed '1d;$d;s/^ *//' | tr '\n' ' ')

  case "$name" in .*) reasons="$reasons hidden file;"; level=2 ;; esac

  if [ -z "$program" ] && [ -z "$(plist_value "$plist" Label)" ]; then
    reasons="$reasons empty file, does nothing (leftover from an old app);"
  elif [ -z "$program" ]; then
    reasons="$reasons no program found;"; [ $level -lt 1 ] && level=1
  elif [ ! -e "$program" ]; then
    reasons="$reasons program is missing;"; [ $level -lt 1 ] && level=1
  else
    if is_temp_location "$program"; then
      reasons="$reasons runs from a temporary/shared folder;"; level=2
    else
      case "$program" in */.*) reasons="$reasons runs from a hidden folder;"; [ $level -lt 1 ] && level=1 ;; esac
    fi
    if is_interpreter "$program"; then
      reasons="$reasons runs a script, check the command;"; [ $level -lt 1 ] && level=1
    fi
    signature=$(signature_of "$program" verify)
    case "$signature" in
      apple) signer="Apple" ;;
      signed:*) signer=${signature#signed:} ;;
      adhoc) signer="ad-hoc (no developer)"; [ $level -lt 1 ] && level=1 ;;
      unreadable) signer="can't check without sudo" ;;
      unsigned) signer="NOT SIGNED"; reasons="$reasons program is not signed;"; level=2 ;;
      invalid:*) signer="BROKEN SIGNATURE"; reasons="$reasons signature does not verify;"; level=2 ;;
    esac
  fi

  if is_recent "$plist"; then
    reasons="$reasons added or changed in the last $RECENT_DAYS days;"; [ $level -lt 1 ] && level=1
  fi

  report_level "$level" "$plist${reasons:+ ->$reasons}"
  info "      runs: $(shorten "${arguments:-${program:-?}}")"
  info "      signed by: $signer | changed: $(fmt_date "$(mtime_of "$plist")")"
}

check_launch_items() {
  subsection "Launch agents and daemons (start automatically)"
  local dirs="$WORK_DIR/launch_dirs" dir plist found=0 user home
  { echo /Library/LaunchAgents; echo /Library/LaunchDaemons
    while IFS='|' read -r user home <&3; do echo "$home/Library/LaunchAgents"; done 3< "$HOMES_FILE"
  } > "$dirs"

  while read -r dir <&4; do
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 1 -type f 2>/dev/null > "$WORK_DIR/plists"
    while read -r plist <&5; do
      found=1
      check_launch_plist "$plist"
    done 5< "$WORK_DIR/plists"
  done 4< "$dirs"
  [ $found -eq 1 ] || ok "No third-party launch agents or daemons"
}

check_background_items() {
  subsection "Login items and background items"
  if [ "$IS_ROOT" -ne 1 ]; then
    skip "Needs sudo (sfltool dumpbtm)"
    return
  fi
  local dump="$REPORT_DIR/background-items.txt"
  if ! sfltool dumpbtm > "$dump" 2>&1; then
    skip "sfltool not available on this macOS version"
    return
  fi
  info "Full list saved to $dump"
  awk '
    function flush() { if (name != "" && type ~ /(legacy|login item|agent|daemon)/) print name "|" dev "|" type "|" disp "|" url; name = dev = type = disp = url = "" }
    /^ *#[0-9]+:/        { flush(); next }
    /^ *Name:/           { sub(/^ *Name: */, "");           name = $0 }
    /^ *Developer Name:/ { sub(/^ *Developer Name: */, ""); dev  = $0 }
    /^ *Type:/           { sub(/^ *Type: */, "");           type = $0 }
    /^ *Disposition:/    { sub(/^ *Disposition: */, "");    disp = $0 }
    /^ *URL:/            { sub(/^ *URL: */, "");            url  = $0 }
    END { flush() }
  ' "$dump" | sort -u | while IFS='|' read -r name dev type disp url; do
    case "$dev" in
      ""|"(null)")
        case "$disp" in *enabled*) warn "Background item with no known developer: $name ($type) $url" ;; *) info "$name (disabled, no developer) $url" ;; esac ;;
      *) info "$name - $dev - $type" ;;
    esac
  done
}

check_other_autostart() {
  subsection "Other auto-start places"
  local tab hook prefs plugin entries

  if [ "$IS_ROOT" -eq 1 ]; then
    for tab in /usr/lib/cron/tabs/*; do
      [ -f "$tab" ] || continue
      warn "Cron jobs for $(basename "$tab")"
      grep -v '^#' "$tab" | indent
    done
  else
    entries=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    [ -n "$entries" ] && { warn "Cron jobs for $(id -un)"; printf '%s\n' "$entries" | indent; }
  fi
  [ -n "$(grep -vE '^[[:space:]]*(#|$)' /etc/crontab 2>/dev/null)" ] && warn "/etc/crontab has entries"
  [ -e /etc/launchd.conf ] && alert "/etc/launchd.conf exists (old persistence trick)"
  [ -n "$(ls -A /Library/StartupItems 2>/dev/null)" ] && warn "/Library/StartupItems is not empty: $(ls -A /Library/StartupItems | tr '\n' ' ')"

  for prefs in /Library/Preferences/com.apple.loginwindow /private/var/root/Library/Preferences/com.apple.loginwindow; do
    for hook in LoginHook LogoutHook; do
      entries=$(defaults read "$prefs" "$hook" 2>/dev/null)
      [ -n "$entries" ] && alert "$hook set: $entries"
    done
  done

  for plugin in /Library/Security/SecurityAgentPlugins/*.bundle; do
    [ -d "$plugin" ] || continue
    warn "Login (authorization) plugin installed: $plugin"
  done
  ok "Checked cron, launchd.conf, StartupItems, login hooks, authorization plugins"
}

check_profiles_and_extensions() {
  subsection "Configuration profiles and device management (MDM)"
  local profiles_output enrollment
  if [ "$IS_ROOT" -eq 1 ]; then
    profiles_output=$(profiles show -all 2>&1)
  else
    profiles_output=$(profiles list 2>&1)
  fi
  if [ -z "$profiles_output" ] || printf '%s' "$profiles_output" | grep -qiE 'no configuration profiles|there are no'; then
    ok "No configuration profiles installed"
  else
    warn "Configuration profiles are installed. Fine if your company manages this Mac; otherwise remove them in System Settings > Privacy & Security > Profiles"
    printf '%s\n' "$profiles_output" | grep -E 'attribute: (name|profileIdentifier|organization)' | sed 's/^ *//' | head -n "$MAX_LIST_ITEMS" | indent
  fi
  enrollment=$(profiles status -type enrollment 2>&1)
  printf '%s' "$enrollment" | grep -q "MDM enrollment: Yes" \
    && warn "This Mac is enrolled in device management (MDM). Make sure it's your company's" \
    || ok "Not enrolled in device management (MDM)"
  if [ -n "$(ls -A '/Library/Managed Preferences' 2>/dev/null)" ]; then
    warn "Managed settings are being pushed to this Mac:"
    ls -A '/Library/Managed Preferences' | indent
  fi

  subsection "System and kernel extensions"
  systemextensionsctl list 2>/dev/null | grep -E '\[activated' | indent
  (kmutil showloaded --list-only 2>/dev/null || kextstat 2>/dev/null) | grep -v 'com.apple' | grep -E '[a-z]+\.[a-z]+\.' | indent
}

check_trusted_certificates() {
  subsection "Extra trusted root certificates (can be used to spy on HTTPS traffic)"
  local certs user home found=0
  certs=$(security dump-trust-settings -d 2>/dev/null | sed -n 's/^Cert [0-9]*: //p')
  if [ -n "$certs" ]; then
    found=1
    printf '%s\n' "$certs" | while read -r cert; do
      warn "System-wide trusted certificate: $cert. Fine if your company/VPN installed it; otherwise delete it in Keychain Access"
    done
  fi
  while IFS='|' read -r user home <&3; do
    certs=$(as_user "$user" security dump-trust-settings 2>/dev/null | sed -n 's/^Cert [0-9]*: //p')
    [ -n "$certs" ] || continue
    found=1
    printf '%s\n' "$certs" | while read -r cert; do
      warn "Certificate trusted by $user: $cert"
    done
  done 3< "$HOMES_FILE"
  [ $found -eq 1 ] || ok "No extra trusted certificates"
}

check_shell_startup_files() {
  subsection "Shell startup files (commands that run every time a terminal opens)"
  local user home file matches files="$WORK_DIR/rcfiles"
  {
    for file in /etc/zshrc /etc/zprofile /etc/zshenv /etc/profile /etc/bashrc; do echo "$file"; done
    while IFS='|' read -r user home <&3; do
      for file in .zshrc .zprofile .zshenv .zlogin .bash_profile .bashrc .profile; do echo "$home/$file"; done
    done 3< "$HOMES_FILE"
  } > "$files"

  while read -r file <&4; do
    [ -f "$file" ] || continue
    matches=$(grep -nE "$SUSPICIOUS_SHELL_PATTERNS" "$file" 2>/dev/null | head -n 10)
    if [ -n "$matches" ]; then
      warn "$file has lines worth a look (downloads, encoded or remote commands)"
      printf '%s\n' "$matches" | cut -c1-"$MAX_TEXT" | indent
    elif is_recent "$file"; then
      info "$file changed $(fmt_date "$(mtime_of "$file")")"
    fi
  done 4< "$files"
  ok "Shell startup files checked"
}

check_chromium_extensions() {
  local user=$1 home=$2 relative browser base version_dir rest profile extension_id details name version access level
  while IFS='|' read -r relative browser <&5; do
    base="$home/Library/Application Support/$relative"
    [ -d "$base" ] || continue
    for version_dir in "$base"/*/Extensions/*/*/; do
      [ -f "${version_dir}manifest.json" ] || continue
      rest=${version_dir#"$base"/}
      profile=${rest%%/*}
      extension_id=$(basename "$(dirname "$version_dir")")
      details=$(json_helper chromium "$version_dir")
      IFS='|' read -r name version access <<EOF
$details
EOF
      level=0
      is_recent "$(dirname "$version_dir")" && level=1
      report_level "$level" "$browser ($user, $profile): $name v$version [$extension_id]${access:+ - can read ALL websites}$([ $level -eq 1 ] && echo " - installed/updated recently")"
    done
  done 5<<EOF
$CHROMIUM_BROWSERS
EOF
}

check_browser_extensions() {
  subsection "Browser extensions (phishing often installs a malicious one)"
  local user home profile_dir safari
  while IFS='|' read -r user home <&3; do
    check_chromium_extensions "$user" "$home"
    for profile_dir in "$home/Library/Application Support/Firefox/Profiles"/*/; do
      [ -f "${profile_dir}extensions.json" ] || continue
      json_helper firefox "${profile_dir}extensions.json" | while IFS='|' read -r name version state; do
        [ -n "$name" ] && info "Firefox ($user): $name v$version ($state)"
      done
    done
    safari=$(as_user "$user" pluginkit -mA -p com.apple.Safari.web-extension 2>/dev/null)
    [ -n "$safari" ] && printf '%s\n' "$safari" | sed 's/^ *//' | while read -r line; do info "Safari ($user): $line"; done
  done 3< "$HOMES_FILE"
  info "Remove any extension you don't recognize, especially ones that can read all websites"
}

check_persistence() {
  section "6. Auto-start items and tampering (signs of compromise)"
  check_launch_items
  check_background_items
  check_other_autostart
  check_profiles_and_extensions
  check_trusted_certificates
  check_shell_startup_files
  check_browser_extensions
}

# ---------------------------------------------------------------- 7. downloads, mail attachments, apps

check_quarantine_history() {
  local user=$1 home=$2 database copy saved separator=$'\x1f' when agent origin data_url bundle shown=0
  database="$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
  [ -f "$database" ] || { info "No download history for $user"; return; }
  copy="$WORK_DIR/quarantine-$user.db"
  copy_sqlite "$database" "$copy" || { skip "Can't read download history for $user (needs Full Disk Access)"; return; }
  saved="$REPORT_DIR/downloads-$user.txt"
  sqlite3 -separator "$separator" "$copy" "
    SELECT datetime(LSQuarantineTimeStamp + $APPLE_EPOCH_OFFSET, 'unixepoch', 'localtime'),
           IFNULL(LSQuarantineAgentName, '?'), IFNULL(LSQuarantineAgentBundleIdentifier, ''),
           IFNULL(LSQuarantineOriginURLString, ''), IFNULL(LSQuarantineDataURLString, '')
    FROM LSQuarantineEvent
    WHERE LSQuarantineTimeStamp + $APPLE_EPOCH_OFFSET > $RECENT_CUTOFF
    ORDER BY LSQuarantineTimeStamp DESC;" 2>/dev/null > "$WORK_DIR/quarantine-$user.txt"

  tr "$separator" '|' < "$WORK_DIR/quarantine-$user.txt" > "$saved"
  info "$user: $(wc -l < "$saved" | tr -d ' ') download(s) in the last $RECENT_DAYS days (full list: $saved)"
  while IFS="$separator" read -r when agent bundle origin data_url <&4; do
    [ -n "$data_url$origin" ] || data_url="(URL not recorded by this macOS version)"
    case "$agent$bundle" in
      *Mail*|*mail*) warn "Opened from Mail on $when: $(shorten "$data_url") ${origin:+(from $(shorten "$origin"))}" ;;
      *)
        [ $shown -lt $QUARANTINE_SCREEN_ROWS ] && info "$when  $agent  $(shorten "${data_url:-$origin}")"
        shown=$((shown + 1)) ;;
    esac
  done 4< "$WORK_DIR/quarantine-$user.txt"
}

check_risky_files() {
  local label=$1 folder=$2 file
  [ -d "$folder" ] || return 0
  if ! ls "$folder" >/dev/null 2>&1; then
    skip "Can't read $folder (needs Full Disk Access)"
    return 0
  fi
  find "$folder" -maxdepth 2 \( -type f -o -name '*.app' -prune \) -mtime -"$RECENT_DAYS" 2>/dev/null \
    | grep -iE "$RISKY_EXTENSIONS" | head -n "$MAX_LIST_ITEMS" > "$WORK_DIR/risky"
  while read -r file <&4; do
    warn "$label: $file ($(fmt_date "$(mtime_of "$file")"))$(where_from "$file")"
  done 4< "$WORK_DIR/risky"
  return 0
}

where_from() {
  local sources
  sources=$(mdls -raw -name kMDItemWhereFroms "$1" 2>/dev/null | sed -n 's/^ *"\(.*\)",*$/\1/p' | tr '\n' ' ')
  [ -n "$sources" ] && printf ' - came from: %s' "$(shorten "$sources")"
}

check_applications() {
  subsection "Applications (signature and notarization)"
  local app result total=0 user home
  {
    find /Applications -maxdepth 2 -name '*.app' -prune -not -path '/Applications/Utilities/*' 2>/dev/null
    while IFS='|' read -r user home <&3; do
      find "$home/Applications" -maxdepth 2 -name '*.app' -prune 2>/dev/null
    done 3< "$HOMES_FILE"
  } > "$WORK_DIR/apps"
  info "Checking $(wc -l < "$WORK_DIR/apps" | tr -d ' ') apps..."

  while read -r app <&4; do
    total=$((total + 1))
    result=$(spctl -a -t exec -vv "$app" 2>&1)
    case "$result" in
      *"not signed at all"*) alert "Unsigned app: $app" ;;
      *rejected*) warn "App rejected by Gatekeeper: $app $(printf '%s' "$result" | sed -n 's/^source=/- /p' | head -1)" ;;
      *) is_recent "$app" && info "Installed/updated recently: $app ($(fmt_date "$(mtime_of "$app")"))" ;;
    esac
  done 4< "$WORK_DIR/apps"
  ok "$total apps checked"
}

check_downloads_and_apps() {
  section "7. Downloads, mail attachments and apps"
  local user home file

  subsection "Download history, last $RECENT_DAYS days (where files came from)"
  while IFS='|' read -r user home <&3; do
    check_quarantine_history "$user" "$home"
  done 3< "$HOMES_FILE"

  subsection "Risky files received recently (installers, archives, scripts, web pages)"
  while IFS='|' read -r user home <&3; do
    check_risky_files "Mail attachment ($user)" "$home/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"
    check_risky_files "Downloads ($user)" "$home/Downloads"
    check_risky_files "Desktop ($user)" "$home/Desktop"
  done 3< "$HOMES_FILE"

  subsection "Executables in temporary, shared or hidden places"
  find /Users/Shared /private/tmp /private/var/tmp -xdev -type f -perm +0111 -mtime -"$RECENT_DAYS" 2>/dev/null \
    | head -n "$MAX_LIST_ITEMS" > "$WORK_DIR/tmp_exec"
  while IFS='|' read -r user home <&3; do
    find "$home" "$home/Library" "$home/Library/Application Support" -maxdepth 1 -name '.*' -type f -perm +0111 2>/dev/null
  done 3< "$HOMES_FILE" >> "$WORK_DIR/tmp_exec"
  while read -r file <&4; do
    warn "Executable file: $file ($(fmt_date "$(mtime_of "$file")"))"
  done 4< "$WORK_DIR/tmp_exec"
  [ -s "$WORK_DIR/tmp_exec" ] || ok "None found"

  check_applications
}

# ---------------------------------------------------------------- 8. processes

check_processes() {
  section "8. Running programs"
  local executable signature signers="$WORK_DIR/signers"
  : > "$signers"
  ps -axwwo comm= 2>/dev/null | sort -u > "$WORK_DIR/processes"

  while read -r executable <&4; do
    case "$executable" in
      /*) ;;
      *) continue ;;
    esac
    case "$executable" in
      /System/*|/usr/*|/bin/*|/sbin/*|/Library/Apple/*|*/Library/Developer/CoreSimulator/*) continue ;;
    esac

    if is_temp_location "$executable"; then
      alert "Program running from a temporary/shared folder: $executable"
    else
      case "$executable" in
        /private/var/folders/*) ;;
        /Volumes/*) warn "Program running from a mounted disk image or drive: $executable" ;;
        */.*) warn "Program running from a hidden folder: $executable" ;;
      esac
    fi

    signature=$(signature_of "$executable")
    case "$signature" in
      unsigned) alert "Unsigned program running: $executable" ;;
      adhoc)
        case "$executable" in
          /opt/homebrew/*|/usr/local/*) ;;
          *) warn "Program without a developer signature running: $executable" ;;
        esac ;;
      signed:*) echo "${signature#signed:}" >> "$signers" ;;
    esac
  done 4< "$WORK_DIR/processes"

  subsection "Developers of the third-party programs running now"
  sed 's/^Apple Mac OS Application Signing$/Mac App Store app/' "$signers" | sort | uniq -c | sort -rn | indent
  info "Anything you don't recognize above deserves a search"
}

# ---------------------------------------------------------------- 9. network

collect_hardware_ports() {
  networksetup -listallhardwareports 2>/dev/null \
    | awk -F': ' '/^Hardware Port:/ { port = $2 } /^Device:/ { print $2 "|" port }' > "$HWPORTS_FILE"
}

port_name() { awk -F'|' -v device="$1" '$1 == device { print $2; exit }' "$HWPORTS_FILE"; }

check_interfaces() {
  subsection "Network interfaces"
  local interface config status ipv4 mac label
  info "$(printf '%-9s %-24s %-9s %-18s %s' INTERFACE TYPE STATUS IPv4 MAC)"
  for interface in $(ifconfig -l); do
    config=$(ifconfig "$interface" 2>/dev/null)
    status=$(printf '%s\n' "$config" | awk '/status:/ { print $2; exit }')
    ipv4=$(printf '%s\n' "$config" | awk '/inet / { print $2 }' | tr '\n' ' ')
    mac=$(printf '%s\n' "$config" | awk '/ether / { print $2; exit }')
    [ "$status" = "active" ] || [ -n "$ipv4" ] || continue
    label=$(port_name "$interface")
    case "$interface" in
      lo*) label="loopback" ;;
      utun*|ipsec*|ppp*|tun*|tap*) label="VPN / tunnel" ;;
    esac
    info "$(printf '%-9s %-24s %-9s %-18s %s' "$interface" "${label:--}" "${status:--}" "${ipv4:--}" "${mac:--}")"
    case "$interface" in
      utun*|ipsec*|ppp*|tun*|tap*)
        [ -n "$ipv4" ] && warn "VPN/tunnel $interface is up with address $ipv4. Fine if you use a VPN; otherwise find out what created it" ;;
    esac
  done
  local vpn_configs
  vpn_configs=$(scutil --nc list 2>/dev/null | sed 1d)
  [ -n "$vpn_configs" ] && { info "VPN configurations:"; printf '%s\n' "$vpn_configs" | indent; }
}

check_dns_and_proxies() {
  subsection "Router, DNS and proxies"
  local gateway interface service servers unknown server proxy_settings wifi_device wifi_summary ssid security
  gateway=$(route -n get default 2>/dev/null | awk '/gateway:/ { print $2 }')
  interface=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
  info "Default gateway (router): ${gateway:-none} via ${interface:-?}"
  info "DNS servers in use: $(scutil --dns 2>/dev/null | awk '/nameserver\[/ { print $3 }' | sort -u | tr '\n' ' ')"

  networksetup -listallnetworkservices 2>/dev/null | sed 1d | sed 's/^\*//' > "$WORK_DIR/services"
  while IFS= read -r service <&4; do
    servers=$(networksetup -getdnsservers "$service" 2>/dev/null)
    case "$servers" in ""|*"aren't any"*) continue ;; esac
    servers=$(printf '%s' "$servers" | tr '\n' ' ')
    unknown=""
    for server in $servers; do
      case " $WELL_KNOWN_DNS " in *" $server "*) ;; *) unknown="$unknown $server" ;; esac
    done
    if [ -n "$unknown" ]; then
      warn "DNS set by hand on '$service': $servers. Unknown DNS servers can send you to fake sites; remove them if you didn't set them"
    else
      info "DNS set by hand on '$service': $servers (well-known public DNS)"
    fi
  done 4< "$WORK_DIR/services"

  proxy_settings=$(scutil --proxy 2>/dev/null)
  if printf '%s\n' "$proxy_settings" | grep -qE '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable) : 1'; then
    warn "A proxy is configured (all web traffic may go through it). Check System Settings > Network > Details > Proxies"
    printf '%s\n' "$proxy_settings" | grep -E '(Proxy|Port|URLString) :' | indent
  else
    ok "No proxy configured"
  fi

  local extra_hosts
  extra_hosts=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE '[[:space:]](localhost|broadcasthost)([[:space:]]|$)')
  if [ -n "$extra_hosts" ]; then
    warn "/etc/hosts has custom entries (can redirect websites)"
    printf '%s\n' "$extra_hosts" | indent
  else
    ok "/etc/hosts is default"
  fi

  wifi_device=$(awk -F'|' '$2 == "Wi-Fi" || $2 == "AirPort" { print $1; exit }' "$HWPORTS_FILE")
  if [ -n "$wifi_device" ]; then
    wifi_summary=$(ipconfig getsummary "$wifi_device" 2>/dev/null)
    ssid=$(printf '%s\n' "$wifi_summary" | awk -F' : ' '/^ *SSID : / { print $2; exit }')
    security=$(printf '%s\n' "$wifi_summary" | awk -F' : ' '/^ *Security : / { print $2; exit }')
    if [ -n "$ssid" ]; then
      info "Wi-Fi network: $ssid (security: ${security:-unknown})"
      case "$security" in *Open*|*None*|*NONE*) warn "Connected to an open Wi-Fi network (no password)" ;; esac
    fi
  fi

  local shares
  shares=$(mount | grep -E 'smbfs|afpfs|nfs|webdav')
  [ -n "$shares" ] && { info "Mounted network shares:"; printf '%s\n' "$shares" | indent; }
  return 0
}

check_connections() {
  subsection "Programs listening for connections"
  [ "$IS_ROOT" -eq 1 ] || info "(without sudo only your own programs are shown)"
  lsof +c 0 -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 { print $1 " (user " $3 ") " $9 }' \
    | sed 's/\\x20/ /g' | sort -u | indent

  subsection "Open connections to the internet, by program"
  lsof +c 0 -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null \
    | awk 'NR > 1 { split($9, ends, "->"); print $1 "  ->  " ends[2] }' \
    | sed 's/\\x20/ /g' | sort | uniq -c | sort -rn | head -n 40 | indent
}

first_lan_interface() {
  local interface
  for interface in $(ifconfig -l); do
    case "$interface" in
      en*) ipconfig getifaddr "$interface" >/dev/null 2>&1 && { echo "$interface"; return; } ;;
    esac
  done
}

ping_sweep() {
  local address=$1 last=$2 own=$3 launched=0
  while [ $address -le $last ]; do
    if [ $address -ne $own ]; then
      ping -c 1 -t 1 -q "$(int_to_ip $address)" >/dev/null 2>&1 &
      launched=$((launched + 1))
      [ $((launched % PING_BATCH_SIZE)) -eq 0 ] && wait
    fi
    address=$((address + 1))
  done
  wait
}

is_random_mac() {
  case "$1" in ?[26aeAE]:*) return 0 ;; esac
  return 1
}

browse_bonjour() {
  local type
  for type in $BONJOUR_TYPES; do
    ( run_with_timeout "$BONJOUR_TIMEOUT" dns-sd -B "$type" local. > "$WORK_DIR/bonjour$type.txt" 2>/dev/null ) &
  done
  wait
  for type in $BONJOUR_TYPES; do
    awk -v type="$type" '$2 == "Add" { name = ""; for (i = 7; i <= NF; i++) name = name (i > 7 ? " " : "") $i; print type "  " name }' \
      "$WORK_DIR/bonjour$type.txt" 2>/dev/null
  done | sort -u
}

discover_lan_devices() {
  subsection "Other devices on the local network"
  if [ "$DO_LAN_SCAN" -ne 1 ]; then
    skip "Disabled with --no-lan-scan"
    return
  fi

  local interface own_ip mask_hex mask own net broadcast prefix gateway hosts device_count ip mac note
  interface=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
  case "$interface" in en*|bridge*) ;; *) interface=$(first_lan_interface) ;; esac
  own_ip=$(ipconfig getifaddr "$interface" 2>/dev/null)
  if [ -z "$own_ip" ]; then
    skip "Not connected to a local network"
    return
  fi
  mask_hex=$(ifconfig "$interface" | awk '/inet / { print $4; exit }')
  mask=$((mask_hex))
  prefix=$(prefix_of_mask $mask)
  if [ "$prefix" -ge 31 ]; then
    skip "Network $own_ip/$prefix is too small to scan"
    return
  fi
  if [ "$prefix" -lt "$MAX_SCAN_PREFIX" ]; then
    info "Network is /$prefix (very large); scanning only the /24 around this Mac"
    mask=$((FALLBACK_SCAN_MASK))
    prefix=24
  fi
  own=$(ip_to_int "$own_ip")
  net=$((own & mask))
  broadcast=$((net | (~mask & 0xffffffff)))
  gateway=$(route -n get default 2>/dev/null | awk '/gateway:/ { print $2 }')

  info "This Mac: $own_ip on $interface. Scanning $(int_to_ip $net)/$prefix (takes a few seconds)..."
  ping_sweep $((net + 1)) $((broadcast - 1)) "$own"

  hosts="$WORK_DIR/lan_hosts"
  arp -an -i "$interface" 2>/dev/null \
    | awk '!/incomplete/ && !/permanent/ && !/ff:ff:ff:ff:ff:ff/ {
        gsub(/[()]/, "", $2)
        n = split($4, octets, ":"); mac = ""
        for (i = 1; i <= n; i++) mac = mac (i > 1 ? ":" : "") (length(octets[i]) == 1 ? "0" : "") octets[i]
        print $2 " " mac
      }' \
    | awk '{ split($1, o, "."); if (o[1] < 224) print }' | sort -t . -k 4,4n -u > "$hosts"
  device_count=$(wc -l < "$hosts" | tr -d ' ')

  info "$(printf '%-16s %-18s %s' IP MAC NOTE)"
  while read -r ip mac <&4; do
    note=""
    [ "$ip" = "$gateway" ] && note="router"
    is_random_mac "$mac" && note="${note:+$note, }private MAC (likely a phone, tablet or laptop)"
    info "$(printf '%-16s %-18s %s' "$ip" "$mac" "$note")"
  done 4< "$hosts"
  ok "Found $device_count other device(s) on the network besides this Mac"
  info "The number can be lower than reality: sleeping devices and devices with a strict firewall don't always answer"

  subsection "Device names announced on the network (Bonjour)"
  browse_bonjour | indent
}

check_network() {
  section "9. Network"
  collect_hardware_ports
  check_interfaces
  check_dns_and_proxies
  check_connections
  discover_lan_devices
}

# ---------------------------------------------------------------- summary and cleanup

print_findings() {
  local level=$1 color=$2 kind section message
  grep "^$level|" "$FINDINGS" | while IFS='|' read -r kind section message; do
    to_both "  ${color}[$kind]${RESET} ($section) $message" "  [$kind] ($section) $message"
  done
}

print_summary() {
  section "Summary"
  local alerts warnings
  alerts=$(grep -c '^ALERT|' "$FINDINGS")
  warnings=$(grep -c '^WARN|' "$FINDINGS")
  info "$alerts alert(s), $warnings warning(s)"

  if [ "$alerts" -gt 0 ]; then
    subsection "Alerts (look at these first)"
    print_findings ALERT "$RED"
  fi
  if [ "$warnings" -gt 0 ]; then
    subsection "Warnings"
    print_findings WARN "$YELLOW"
  fi

  subsection "What was not checked"
  [ "$IS_ROOT" -eq 1 ] || info "Ran without sudo: other users, login items, sudoers and other programs' connections were skipped. Run again with: sudo $0"
  [ "$HAS_FULL_DISK_ACCESS" -eq 1 ] || info "Terminal has no Full Disk Access, so Mail attachments and some Library folders may be missing. Add Terminal in System Settings > Privacy & Security > Full Disk Access, then run again"
  [ "$IS_ROOT" -eq 1 ] && [ "$HAS_FULL_DISK_ACCESS" -eq 1 ] && info "Nothing, full coverage"

  subsection "After a phishing email"
  info "1. If a password was typed on a page from the email: change it now FROM ANOTHER DEVICE, turn on 2FA and sign out all other sessions."
  info "2. In that email account, look for forwarding rules, filters, app passwords and connected apps you didn't create; attackers add them to keep reading your mail."
  info "3. If a file from the email was opened (see 'Opened from Mail' and 'Mail attachment' above), the safest fix is to back up documents (not apps) and erase and reinstall macOS."
  info "4. A clean report does not prove the Mac is clean; it means none of these known signs were found."
  info ""
  info "Full report: $REPORT"
}

delete_contents() {
  local home=$1 path=$2
  [ -n "$home" ] && [ "$home" != "/" ] || return 1
  case "$path" in "$home"/?*) ;; *) return 1 ;; esac
  [ -d "$path" ] && [ ! -L "$path" ] || return 1
  find "$path" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
  [ -z "$(ls -A "$path" 2>/dev/null)" ]
}

run_cleanup() {
  section "Cleanup"
  if [ ! -t 0 ]; then
    skip "Not running in an interactive terminal, cleanup needs your answers"
    return
  fi
  if [ ! -s "$CLEAN_CANDIDATES" ]; then
    info "Nothing safe to clean"
    return
  fi

  local alerts answer kb home path description
  alerts=$(grep -c '^ALERT|' "$FINDINGS")
  info "Deleting caches also deletes evidence (browser history caches, logs) of what happened after the phishing email."
  [ "$alerts" -gt 0 ] && to_both "  ${RED}The audit found $alerts ALERT(s). Look at them before deleting anything.${RESET}" "  The audit found $alerts ALERT(s). Look at them before deleting anything."
  info "Quit your browsers and other apps before continuing."
  read -r -p "    Type YES to start the cleanup: " answer </dev/tty
  if [ "$answer" != "YES" ]; then
    info "Cleanup cancelled, nothing deleted"
    return
  fi

  sort -t'|' -k1,1rn "$CLEAN_CANDIDATES" > "$WORK_DIR/clean_sorted"
  while IFS='|' read -r kb home path description <&4; do
    read -r -p "    Delete the contents of $path ($(human_kb "$kb"), $description)? [y/N] " answer </dev/tty
    case "$answer" in
      y|Y)
        if delete_contents "$home" "$path"; then
          ok "Cleaned $path"
        else
          info "Cleaned $path partly (some files are in use or protected by macOS)"
        fi ;;
      *) info "Kept $path" ;;
    esac
  done 4< "$WORK_DIR/clean_sorted"

  subsection "Disk after cleanup"
  df -hl / /System/Volumes/Data 2>/dev/null | indent
}

# ---------------------------------------------------------------- main

main() {
  collect_target_homes
  write_json_helper
  HAS_FULL_DISK_ACCESS=0
  detect_full_disk_access && HAS_FULL_DISK_ACCESS=1

  to_both "${BOLD}macOS audit - $(date '+%Y-%m-%d %H:%M:%S')${RESET}" "macOS audit - $(date '+%Y-%m-%d %H:%M:%S')"
  info "Run by: $INVOKING_USER  |  sudo: $([ "$IS_ROOT" -eq 1 ] && echo yes || echo no)  |  Full Disk Access: $([ "$HAS_FULL_DISK_ACCESS" -eq 1 ] && echo yes || echo no)"
  info "Recent = last $RECENT_DAYS days  |  Users checked: $(cut -d'|' -f1 "$HOMES_FILE" | tr '\n' ' ')"
  info "Report folder: $REPORT_DIR"

  check_system
  check_disk
  check_caches
  check_users
  check_security_settings
  check_persistence
  check_downloads_and_apps
  check_processes
  check_network
  print_summary
  [ "$DO_CLEAN" -eq 1 ] && run_cleanup

  [ "$IS_ROOT" -eq 1 ] && [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$REPORT_DIR"
  return 0
}

main
