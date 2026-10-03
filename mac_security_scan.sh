#!/bin/bash
#
# mac_security_scan.sh - Deep security & secrets scan for macOS (read-only)
#
#   1. System protection   updates, SIP, Gatekeeper, FileVault, firewall, XProtect
#   2. Accounts & sign-in  auto-login, guest, root, admins, screen lock, Secure Token
#   3. Network & sharing   open ports, remote access, Wi-Fi, DNS, proxy, hosts file
#   4. Persistence/malware startup items, kexts, processes, apps, root certificates
#   5. File scan           every readable file: API keys, tokens, private keys,
#                          passwords in notes/history/config, wallet seed phrases,
#                          card numbers, unsafe permissions, unsigned programs
#   6. Logs                failed logins, sudo failures, malware detections
#   -> HTML report (opens automatically), issues sorted Critical / High / Medium / Low
#
# Usage
#   ./mac_security_scan.sh                 your account + shared/system config
#   sudo ./mac_security_scan.sh            every user account + admin-only checks
#   ./mac_security_scan.sh --path ~/Code   scan only this folder (repeatable)
#   ./mac_security_scan.sh --full          whole disk (slow)
#   Options: --max-size MB (default 5)  --include-cloud  --no-open  --system-only
#
# Before running: System Settings > Privacy & Security > Full Disk Access > Terminal ON
# (otherwise macOS hides Desktop/Documents/Downloads from the scan).
# Nothing is changed on the Mac. Secrets are never written in full - only masked.

VERSION="2.0"
[ "$(uname)" = "Darwin" ] || { echo "This script only runs on macOS."; exit 1; }

# ------------------------------------------------------------------ options
MAX_MB=5; OPEN_REPORT=1; FULL=0; SYSTEM_ONLY=0; INCLUDE_CLOUD=0; CUSTOM_ROOTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --path) [ -d "$2" ] || { echo "Not a folder: $2"; exit 1; }
            CUSTOM_ROOTS="$CUSTOM_ROOTS$(cd "$2" && pwd)
"; shift ;;
    --full) FULL=1 ;;
    --max-size) MAX_MB="$2"; shift ;;
    --include-cloud) INCLUDE_CLOUD=1 ;;
    --no-open) OPEN_REPORT=0 ;;
    --system-only) SYSTEM_ONLY=1 ;;
    -h|--help) sed -n '3,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1  (see --help)"; exit 1 ;;
  esac
  shift
done

# ------------------------------------------------------------------ helpers
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
exec </dev/null                                   # never wait on keyboard input
sudo() { command sudo -n "$@"; }                  # never prompt for a password
tmo() { local t=$1; shift; perl -e 'alarm shift; exec @ARGV or exit 127' "$t" "$@" 2>/dev/null; }

if [ -t 1 ]; then
  IS_TTY=1; B=$'\033[1m'; D=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'
  GRN=$'\033[32m'; CYN=$'\033[36m'; R=$'\033[0m'
  COLS=$(stty size </dev/tty 2>/dev/null | awk '{print $2}')
else
  IS_TTY=0; B=; D=; RED=; YEL=; GRN=; CYN=; R=
fi
COLS=${COLS:-100}

REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -d "$REAL_HOME" ] || REAL_HOME="$HOME"
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

STAMP=$(date +%Y-%m-%d_%H%M%S)
OUTDIR="$REAL_HOME/SecurityScans/$STAMP"
mkdir -p "$OUTDIR" && chmod 700 "$REAL_HOME/SecurityScans" "$OUTDIR" || { echo "Cannot create $OUTDIR"; exit 1; }
FINDINGS="$OUTDIR/findings.tsv"; META="$OUTDIR/.meta"; INVENTORY="$OUTDIR/inventory.txt"
: > "$FINDINGS"; : > "$META"; : > "$INVENTORY"
START_TS=$(date +%s); INTERRUPTED=0

# add SEV CATEGORY TITLE LOCATION EVIDENCE ACTION      (SEV 1=Critical 2=High 3=Medium 4=Low)
add() {
  local out="" f
  for f in "$1" "$2" "$3" "$4" "$5" "$6"; do
    out="$out$(printf '%s' "$f" | tr '\t\r\n' '   ')	"
  done
  printf '%s\n' "${out%	}" >> "$FINDINGS"
}
meta() { printf '%s=%s\n' "$1" "$(printf '%s' "$2" | tr '\n' ' ')" >> "$META"; }
inv()  { printf '%s\n' "$*" >> "$INVENTORY"; }
nfind() { wc -l < "$FINDINGS" | tr -d ' '; }

PH_NUM=""; PH_NAME=""; PH_START=0; PH_T0=0
status() {
  [ "$IS_TTY" = 1 ] || return 0
  local msg="$1"; local max=$((COLS - ${#PH_NAME} - 14)); [ $max -lt 10 ] && max=10
  [ ${#msg} -gt $max ] && msg="${msg:0:$max}"
  printf '\r\033[K  %s[%s]%s %s %s%s%s' "$CYN" "$PH_NUM" "$R" "$PH_NAME" "$D" "$msg" "$R"
}
phase() { PH_NUM=$1; PH_NAME=$2; PH_START=$(nfind); PH_T0=$(date +%s); status "starting..."; }
phase_done() {
  local n=$(( $(nfind) - PH_START )); local dt=$(( $(date +%s) - PH_T0 ))
  [ "$IS_TTY" = 1 ] && printf '\r\033[K'
  if [ "$n" -gt 0 ]; then
    printf '  %s✓%s [%s] %-28s %s%3d finding(s)%s %s%ss%s\n' "$GRN" "$R" "$PH_NUM" "$PH_NAME" "$YEL" "$n" "$R" "$D" "$dt" "$R"
  else
    printf '  %s✓%s [%s] %-28s %s      no issues%s %s%ss%s\n' "$GRN" "$R" "$PH_NUM" "$PH_NAME" "$GRN" "$R" "$D" "$dt" "$R"
  fi
}

# ------------------------------------------------------------------ banner
HOSTNAME_=$(scutil --get ComputerName 2>/dev/null || hostname)
OSV=$(sw_vers -productVersion); BLD=$(sw_vers -buildVersion)
echo
printf '  %smacOS Deep Security Scan%s %sv%s%s\n' "$B" "$R" "$D" "$VERSION" "$R"
printf '  %s%s  ·  macOS %s  ·  %s  ·  %s%s\n' "$D" "$HOSTNAME_" "$OSV" "$REAL_USER" \
  "$([ $IS_ROOT = 1 ] && echo 'admin mode: all users' || echo 'standard mode: your account')" "$R"
meta host "$HOSTNAME_"; meta os "macOS $OSV ($BLD) $(uname -m)"; meta user "$REAL_USER"
meta mode "$([ $IS_ROOT = 1 ] && echo 'admin (sudo) - all users' || echo 'standard - current user only')"
meta started "$(date '+%Y-%m-%d %H:%M')"; meta home "$REAL_HOME"

# Full Disk Access check (reading the user TCC database only works with FDA, no prompt)
FDA=0
head -c 1 "$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db" >/dev/null 2>&1 && FDA=1
meta fda "$([ $FDA = 1 ] && echo yes || echo no)"
if [ $FDA = 0 ] && [ $SYSTEM_ONLY = 0 ]; then
  echo
  printf '  %s!%s Terminal does not have %sFull Disk Access%s.\n' "$YEL" "$R" "$B" "$R"
  echo "    macOS will hide Desktop, Documents and Downloads, so those folders get skipped."
  echo "    Fix: System Settings > Privacy & Security > Full Disk Access > turn on Terminal,"
  echo "    then quit Terminal (Cmd+Q), reopen it and run this script again."
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" >/dev/null 2>&1
  if [ "$IS_TTY" = 1 ]; then
    printf '    %sPress Enter to continue with a limited scan, or Ctrl+C to stop (auto-continue in 30s)%s ' "$D" "$R"
    read -r -t 30 _ </dev/tty 2>/dev/null; echo
  fi
  add 4 "Coverage" "Scan was incomplete: Terminal lacks Full Disk Access" "System Settings > Privacy & Security > Full Disk Access" \
    "Desktop, Documents, Downloads and app data were not scanned" \
    "Turn on Full Disk Access for Terminal, restart Terminal and run the scan again for full coverage."
fi
echo

# ================================================================== 1. SYSTEM
phase "1/6" "System protection"
MAJOR=${OSV%%.*}; MINOR=$(printf '%s' "$OSV" | cut -d. -f2); case "$MINOR" in ''|*[!0-9]*) MINOR=0 ;; esac

status "asking Apple for available updates (up to 90s)"
UPD=$(tmo 90 softwareupdate --list 2>&1)
LABELS=$(printf '%s\n' "$UPD" | sed -n 's/^.*Label: //p')
if [ -n "$LABELS" ]; then
  L1=$(printf '%s\n' "$LABELS" | head -6 | paste -sd ';' -)
  if printf '%s\n' "$LABELS" | grep -qiE 'macOS|Security|Background|Rapid|XProtect'; then
    add 1 "Updates" "macOS security updates are waiting to be installed" "Software Update" "$L1" \
      "Open System Settings > General > Software Update, install everything and restart. Most Mac attacks use bugs these updates already fix."
  else
    add 3 "Updates" "Software updates are waiting to be installed" "Software Update" "$L1" \
      "Install them from System Settings > General > Software Update."
  fi
fi
if [ "$MAJOR" -le 13 ]; then
  add 1 "Updates" "This macOS version no longer gets security fixes" "macOS $OSV" "Apple only patches the three newest major versions" \
    "Upgrade macOS (System Settings > General > Software Update). An M1 Mac supports the newest versions."
elif { [ "$MAJOR" -eq 15 ] && [ "$MINOR" -lt 7 ]; } || { [ "$MAJOR" -eq 14 ] && [ "$MINOR" -lt 8 ]; }; then
  add 2 "Updates" "macOS is missing many months of security fixes" "macOS $OSV" "Later $MAJOR.x releases fix actively exploited vulnerabilities" \
    "Update to the latest macOS (System Settings > General > Software Update)."
fi

status "automatic update settings"
SUP=/Library/Preferences/com.apple.SoftwareUpdate
for spec in "AutomaticCheckEnabled|Automatic update checks are turned off|2" \
            "AutomaticDownload|Updates are not downloaded automatically|3" \
            "CriticalUpdateInstall|Security Responses are not installed automatically|2" \
            "ConfigDataInstall|Malware definitions (XProtect) are not installed automatically|2"; do
  k=${spec%%|*}; rest=${spec#*|}; t=${rest%|*}; s=${rest##*|}
  [ "$(defaults read $SUP "$k" 2>/dev/null)" = "0" ] && add "$s" "Updates" "$t" "$SUP" "$k = 0" \
    "System Settings > General > Software Update > (i) next to Automatic Updates: turn every option on."
done

status "SIP, Gatekeeper, FileVault, firewall"
SIP=$(csrutil status 2>&1)
printf '%s' "$SIP" | grep -q 'status: enabled\.' || add 1 "System" "System Integrity Protection (SIP) is off or weakened" "csrutil" "$SIP" \
  "Restart into Recovery (hold power button > Options), open Terminal and run: csrutil enable"
AR=$(csrutil authenticated-root status 2>&1)
printf '%s' "$AR" | grep -qi 'disabled' && add 1 "System" "Sealed system volume protection is off" "csrutil authenticated-root" "$AR" \
  "In Recovery Terminal run: csrutil authenticated-root enable"
GK=$(spctl --status 2>&1)
printf '%s' "$GK" | grep -q 'assessments enabled' || add 1 "System" "Gatekeeper (app safety check) is turned off" "spctl" "$GK" \
  "Run: sudo spctl --global-enable   then System Settings > Privacy & Security > allow apps from App Store and identified developers."
FV=$(fdesetup status 2>&1)
printf '%s' "$FV" | grep -q 'FileVault is On' || add 2 "System" "FileVault disk encryption is off" "fdesetup" "$FV" \
  "System Settings > Privacy & Security > FileVault > Turn On. If the Mac is lost or stolen, nobody can read your files."
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)
printf '%s' "$FW" | grep -qi 'disabled\|State = 0' && add 3 "Network" "Firewall is turned off" "Application Firewall" "$FW" \
  "System Settings > Network > Firewall > turn on."
ST=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1)
printf '%s' "$FW" | grep -qi 'disabled\|State = 0' || { printf '%s' "$ST" | grep -qi 'on\b\|enabled' || \
  add 4 "Network" "Firewall stealth mode is off" "Application Firewall" "$ST" "Network > Firewall > Options > Enable stealth mode."; }

status "XProtect malware definitions"
XPB=/Library/Apple/System/Library/CoreServices/XProtect.bundle
XPV=$(defaults read "$XPB/Contents/Info" CFBundleShortVersionString 2>/dev/null)
XPT=$(stat -f %m "$XPB/Contents/Info.plist" 2>/dev/null)
if [ -z "$XPV" ]; then
  add 2 "System" "Built-in malware protection (XProtect) not found" "$XPB" "missing" "Run Software Update to restore it."
else
  XAGE=$(( ( $(date +%s) - ${XPT:-0} ) / 86400 )); meta xprotect "version $XPV, $XAGE days old"
  [ "$XAGE" -gt 45 ] && add 2 "System" "Malware definitions (XProtect) are $XAGE days old" "$XPB" "version $XPV" \
    "Apple updates XProtect every few weeks. Turn on 'Install Security Responses and system files' and run Software Update."
fi

status "boot and code-signing settings"
BA=$(nvram boot-args 2>/dev/null | cut -f2-)
printf '%s' "$BA" | grep -qE 'amfi_get_out_of_my_way|cs_enforcement_disable|amfi=|-arm64e_preview_abi' && \
  add 1 "System" "Code-signing enforcement is disabled at boot" "nvram boot-args" "$BA" "Remove it: sudo nvram -d boot-args  then restart."
[ "$(defaults read /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation 2>/dev/null)" = "1" ] && \
  add 2 "System" "Library validation is disabled (lets unsigned code load into apps)" "com.apple.security.libraryvalidation" "DisableLibraryValidation = 1" \
  "sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation"
ENR=$(tmo 10 profiles status -type enrollment 2>&1)
printf '%s' "$ENR" | grep -qi 'MDM enrollment: Yes' && add 3 "System" "This Mac is remotely managed (MDM)" "profiles" "$ENR" \
  "Fine for a work Mac. On a personal Mac, check System Settings > Privacy & Security > Profiles and remove anything you don't recognise."
nvram -p 2>/dev/null | grep -q 'fmm-mobileme-token-FMM' || add 4 "System" "Find My Mac appears to be off" "Find My" "no Find My token" \
  "System Settings > [your name] > iCloud > Find My Mac > On, so you can lock or erase it if lost."
phase_done

# ================================================================== 2. ACCOUNTS
phase "2/6" "Accounts & sign-in"
USERS=$(dscl . list /Users UniqueID | awk '$2>=501 && $1 !~ /^_/ {print $1}')
ADMINS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2- | tr ' ' '\n' | grep -v '^root$' | grep -v '^$')
NADM=$(printf '%s\n' "$ADMINS" | grep -c .)
inv "== Users"
for u in $USERS; do
  status "user $u"
  ROLE=standard; printf '%s\n' "$ADMINS" | grep -qx "$u" && ROLE=admin
  TK=$(tmo 10 sysadminctl -secureTokenStatus "$u" 2>&1 | grep -oE 'ENABLED|DISABLED' | head -1)
  inv "$u  role=$ROLE  secure_token=${TK:-unknown}"
  [ "$TK" = "DISABLED" ] && add 3 "Accounts" "User '$u' has no Secure Token" "$u" "Secure Token: DISABLED" \
    "This can cause login and FileVault problems. As an admin run: sysadminctl -secureTokenOn $u -password - -adminUser <admin> -adminPassword -"
done
inv ""
[ "$NADM" -gt 1 ] && add 4 "Accounts" "More than one administrator account" "Users & Groups" "Admins: $(echo $ADMINS)" \
  "Give everyday users Standard accounts; keep admin rights to one person."
RP=$(dscl . -read /Users/root Password 2>/dev/null | awk '{print $2}')
[ -n "$RP" ] && [ "$RP" != "*" ] && add 2 "Accounts" "The root (superuser) account is enabled" "/Users/root" "root has a password" \
  "Disable it: Directory Utility > Edit > Disable Root User (or: dsenableroot -d)."
LW=/Library/Preferences/com.apple.loginwindow
AUTO=$(defaults read $LW autoLoginUser 2>/dev/null)
[ -n "$AUTO" ] && add 2 "Accounts" "Automatic login is on (no password at startup)" "$LW" "autoLoginUser = $AUTO" \
  "System Settings > Users & Groups > Automatically log in as: Off."
[ "$(defaults read $LW GuestEnabled 2>/dev/null)" = "1" ] && add 3 "Accounts" "Guest account is enabled" "$LW" "GuestEnabled = 1" \
  "System Settings > Users & Groups > Guest User > turn off."
HINT=$(defaults read $LW RetriesUntilHint 2>/dev/null)
[ -n "$HINT" ] && [ "$HINT" != "0" ] && add 4 "Accounts" "Password hints are shown at login" "$LW" "RetriesUntilHint = $HINT" \
  "System Settings > Lock Screen > Show password hints: off."
SL=$(tmo 10 sysadminctl -screenLock status 2>&1)
case "$SL" in
  *"is off"*) add 2 "Accounts" "No password needed after sleep or screen saver" "Lock Screen" "$SL" \
                "System Settings > Lock Screen > Require password after screen saver begins or display is turned off: Immediately." ;;
  *"delay is "*) SLD=$(printf '%s' "$SL" | sed -n 's/.*delay is \([0-9][0-9]*\) seconds.*/\1/p')
                 [ -n "$SLD" ] && [ "$SLD" -gt 300 ] && add 3 "Accounts" "Screen lock waits $SLD seconds before asking for a password" "Lock Screen" "$SL" \
                   "System Settings > Lock Screen > require password: Immediately." ;;
esac
NP=$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -5 | paste -sd ';' -)
[ -n "$NP" ] && add 2 "Accounts" "sudo is allowed without a password" "/etc/sudoers" "$NP" "Remove NOPASSWD rules with: sudo visudo"
TMD=$(tmo 15 tmutil destinationinfo 2>&1)
printf '%s' "$TMD" | grep -qi 'No destinations' && add 3 "Backup" "No Time Machine backup is set up" "Time Machine" "No destinations configured" \
  "Set up Time Machine on an external drive (System Settings > General > Time Machine) with encryption on. Backups are your best defence against ransomware and disk failure."
phase_done

# ================================================================== 3. NETWORK
phase "3/6" "Network & sharing"
for spec in "22|Remote Login (SSH)|2" "5900|Screen Sharing / Remote Management|2" "3283|Apple Remote Desktop|2" \
            "3031|Remote Apple Events|2" "445|File Sharing (SMB)|3" "548|File Sharing (AFP)|3" \
            "631|Printer Sharing|4" "3689|Media Sharing|4"; do
  p=${spec%%|*}; rest=${spec#*|}; n=${rest%|*}; s=${rest##*|}
  status "checking $n"
  tmo 3 nc -z 127.0.0.1 "$p" >/dev/null 2>&1 && add "$s" "Sharing" "$n is turned on" "TCP port $p" \
    "Other devices on the same network can try to log in to this service" \
    "If you don't use it: System Settings > General > Sharing > turn off $n."
done
status "listening network services"
LST=$(tmo 20 lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1" "$3" "$9}' | sort -u)
inv "== Listening TCP services (process user address)"; inv "$LST"; inv ""
EXP=$(printf '%s\n' "$LST" | awk '$3 ~ /^(\*|0\.0\.0\.0|\[::\]):/' | \
  grep -vE '^(rapportd|ControlCe|sharingd|identitys|launchd|remoted|AirPlayXP|mDNSRespo|netbiosd|smbd|sshd|screensha|ARDAgent|cupsd|com\.apple) ' | \
  awk '{print $1" ("$3")"}' | sort -u | head -12 | paste -sd ';' -)
[ -n "$EXP" ] && add 3 "Network" "Apps are accepting connections from the network" "$EXP" "listening on all interfaces" \
  "Make sure you recognise each app. Developer servers should listen on 127.0.0.1 only; quit or uninstall anything unknown."
status "Wi-Fi security"
WIFI=$(tmo 25 system_profiler SPAirPortDataType 2>/dev/null | awk '/Current Network Information:/{f=1;next} f && /Security:/{print; exit}' | sed 's/^ *//')
case "$WIFI" in
  *None*|*Open*) add 2 "Network" "Connected to an unencrypted (open) Wi-Fi network" "Wi-Fi" "$WIFI" \
                   "Others nearby can see your traffic. Use a password-protected (WPA2/WPA3) network or a VPN." ;;
  *WEP*|*"WPA Personal"*) add 3 "Network" "Wi-Fi uses outdated encryption" "Wi-Fi" "$WIFI" "Switch the router to WPA2 or WPA3." ;;
esac
status "proxy, DNS, hosts file"
PROXY=$(scutil --proxy 2>/dev/null | grep -E '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable) : 1')
[ -n "$PROXY" ] && add 2 "Network" "A system-wide proxy is configured" "Network settings" \
  "$(scutil --proxy | grep -E 'Proxy :|Port :|URLString' | sed 's/^ *//' | head -6 | paste -sd ';' -)" \
  "If you didn't set this up (VPN/work), remove it in System Settings > Network > Details > Proxies. Malware uses proxies to spy on traffic."
HOSTS=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE '(^|[[:space:]])(localhost|broadcasthost)([[:space:]]|$)' | head -8 | paste -sd ';' -)
[ -n "$HOSTS" ] && add 3 "Network" "Custom entries in /etc/hosts" "/etc/hosts" "$HOSTS" \
  "Remove lines you didn't add (sudo nano /etc/hosts). Malware edits this file to redirect websites."
DNS=$(scutil --dns 2>/dev/null | awk '/nameserver\[/ {print $3}' | sort -u)
inv "== DNS servers"; inv "$DNS"; inv ""
ODD=$(printf '%s\n' "$DNS" | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|100\.100\.100\.100|fe80|fd|f[cd][0-9a-f]{2}:|1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|149\.112\.112\.112|208\.67\.22[02]\.22[02]|94\.140\.1[45]\.1[45]|2606:4700|2001:4860)' | grep . | paste -sd ';' -)
[ -n "$ODD" ] && add 4 "Network" "DNS servers are not your router or a well-known provider" "Network > DNS" "$ODD" \
  "Usually your internet provider - fine. If you don't recognise them, reset DNS in System Settings > Network > Details > DNS."
[ "$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -c 'Enabled = 1')" -gt 0 ] && \
  add 3 "Sharing" "Internet Sharing is turned on" "Sharing" "NAT enabled" "System Settings > General > Sharing > Internet Sharing: off if unused."
[ "$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null)" = "Everyone" ] && \
  add 4 "Sharing" "AirDrop is open to everyone" "AirDrop" "DiscoverableMode = Everyone" "Control Center > AirDrop > Contacts Only."
phase_done

# ================================================================== 4. PERSISTENCE / MALWARE
phase "4/6" "Startup items, apps & malware"
inv "== Startup items (launch agents/daemons): label | program | signer"
LA_DIRS="/Library/LaunchAgents /Library/LaunchDaemons"
if [ $IS_ROOT = 1 ]; then
  for h in $(dscl . list /Users NFSHomeDirectory | awk '$2 ~ /^\/Users\// {print $2}'); do LA_DIRS="$LA_DIRS $h/Library/LaunchAgents"; done
else
  LA_DIRS="$LA_DIRS $REAL_HOME/Library/LaunchAgents"
fi
for dir in $LA_DIRS; do
  [ -d "$dir" ] || continue
  for p in "$dir"/*.plist; do
    [ -f "$p" ] || continue
    status "$(basename "$p")"
    PB=/usr/libexec/PlistBuddy
    lbl=$($PB -c "Print :Label" "$p" 2>/dev/null)
    prog=$($PB -c "Print :Program" "$p" 2>/dev/null)
    args=$($PB -c "Print :ProgramArguments" "$p" 2>/dev/null | sed '1d;$d;s/^ *//' | paste -sd ' ' -)
    [ -z "$prog" ] && prog=$($PB -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
    signer=""
    if [ -n "$prog" ] && [ -f "$prog" ]; then
      signer=$(tmo 15 codesign -dv --verbose=2 "$prog" 2>&1 | sed -n 's/^Authority=//p' | head -1)
    fi
    inv "${lbl:-?} | ${prog:-?} | ${signer:-unsigned/unknown}  [$p]"
    case "$prog" in
      /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/Users/Shared/*|*/Downloads/*|*/Library/Caches/*)
        add 1 "Persistence" "Startup item runs a program from a temporary or shared folder" "$p" "$prog $args" \
          "Malware often hides here. If you don't recognise it: launchctl bootout, delete the .plist and the program, then run a malware scan (e.g. Malwarebytes)."
        continue ;;
    esac
    case "$(basename "${prog:-x}")" in
      sh|bash|zsh|dash|python|python3|perl|ruby|osascript|node|curl|wget)
        if printf '%s' "$args" | grep -qiE 'curl|wget|base64|https?://|/tmp/|\| *(ba|z)?sh|osascript -e'; then
          add 1 "Persistence" "Startup item downloads or decodes code every time you log in" "$p" "$(printf '%s' "$args" | cut -c1-200)" \
            "If you didn't install this on purpose, remove it (launchctl bootout + delete the .plist) and run a malware scan."
        else
          add 3 "Persistence" "Startup item runs a script" "$p" "$(printf '%s' "$args" | cut -c1-200)" \
            "Check you recognise it. Scripts started at login are a common malware trick."
        fi ;;
    esac
    if printf '%s' "$prog" | grep -qE '/\.[^/]+/'; then
      add 2 "Persistence" "Startup item runs a program from a hidden folder" "$p" "$prog" \
        "Hidden folders are a common malware trick. Remove it if you don't recognise it."
    fi
    if [ -n "$prog" ] && [ ! -e "$prog" ]; then
      add 4 "Persistence" "Startup item points to a program that no longer exists" "$p" "$prog" "Leftover from an uninstalled app. Delete the .plist."
    elif [ -f "$prog" ]; then
      if ! tmo 15 codesign -v "$prog" >/dev/null 2>&1; then
        add 2 "Persistence" "Startup item program is unsigned or its signature is broken" "$p" "$prog" \
          "Make sure the software is trustworthy; reinstall it from the vendor or remove it."
      fi
      case "$lbl" in com.apple.*)
        case "$signer" in "Software Signing"|Apple*) ;; *)
          add 2 "Persistence" "Startup item pretends to be from Apple" "$p" "$lbl -> $prog (signer: ${signer:-none})" \
            "Real Apple items live in /System. Investigate and remove it if unknown." ;;
        esac ;;
      esac
    fi
  done
done
inv ""

status "cron jobs"
CR=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | head -5 | paste -sd ';' -)
[ -n "$CR" ] && add 3 "Persistence" "Scheduled cron jobs exist" "crontab -l" "$CR" "Check each job is yours (crontab -e to edit)."
status "kernel and system extensions"
KX=$(tmo 20 kmutil showloaded --list-only 2>/dev/null | grep -v 'com\.apple' | awk '{print $NF}' | grep -v '^$' | head -8 | paste -sd ';' -)
[ -n "$KX" ] && add 3 "Persistence" "Third-party kernel extensions are loaded" "kmutil" "$KX" \
  "Kernel extensions run with full control of the Mac. Remove software you no longer use."
SX=$(tmo 15 systemextensionsctl list 2>/dev/null | grep 'activated enabled' | grep -v 'com\.apple')
inv "== System extensions"; inv "$SX"; inv ""

status "running processes"
PSL=$(ps -axww -o pid=,user=,comm= 2>/dev/null)
BADP=$(printf '%s\n' "$PSL" | awk '$3 ~ /^\/(private\/)?(tmp|var\/tmp)\// || $3 ~ /^\/Users\/Shared\// || $3 ~ /\/\.[^\/]+\/[^\/]+$/' | head -8 | paste -sd ';' -)
[ -n "$BADP" ] && add 1 "Malware" "Programs are running from temporary, shared or hidden folders" "ps" "$BADP" \
  "Look these up (lsof -p <pid>). If unknown, quit them, delete the files and run a malware scan."
KNOWN='xmrig|kinsing|cpuminer|minerd|MacKeeper|Genieo|Shlayer|AdLoad|Bundlore|WizardUpdate|Pirrit|VSearch|Atomic|AMOS|Cuckoo|Poseidon|Banshee|RustBucket|KandyKorn|XLoader|JokerSpy'
KB=$(printf '%s\n' "$PSL" | awk '{print $3}' | grep -iE "/($KNOWN)[^/]*$" | head -5 | paste -sd ';' -)
[ -n "$KB" ] && add 1 "Malware" "A process name matches known Mac malware or adware" "ps" "$KB" \
  "Disconnect from the internet, run Malwarebytes, and change important passwords from another device."
HOT=$(ps -axo pcpu=,comm= -r 2>/dev/null | awk '$1>90 {print $2" ("$1"%)"}' | head -3 | paste -sd ';' -)
[ -n "$HOT" ] && add 4 "Malware" "Something is using almost all of the CPU" "ps" "$HOT" \
  "Check Activity Monitor. If you don't recognise it, it could be a crypto-miner."

status "installed applications"
PUP='MacKeeper|Advanced Mac Cleaner|Mac Auto Fixer|Genieo|Spigot|MacCleaner Pro|Mac Adware Cleaner|Search Baron|OneStart|Mac Tonic|MacBooster|Similar Photo Cleaner'
PA=$(ls /Applications "$REAL_HOME/Applications" 2>/dev/null | grep -iE "$PUP" | head -5 | paste -sd ';' -)
[ -n "$PA" ] && add 2 "Malware" "Known adware or scam 'cleaner' apps are installed" "/Applications" "$PA" \
  "Uninstall them (drag to Trash) and remove their startup items."
inv "== Applications: name | signature | Gatekeeper"
for app in /Applications/*.app "$REAL_HOME"/Applications/*.app; do
  [ -d "$app" ] || continue
  an=$(basename "$app"); status "checking app $an"
  bid=$(defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null)
  case "$bid" in com.apple.*) continue ;; esac
  sig=ok; tmo 20 codesign -v "$app" >/dev/null 2>&1 || sig=bad
  gk=ok;  tmo 15 spctl -a -t exec "$app" >/dev/null 2>&1 || gk=rejected
  inv "$an | $sig | $gk"
  if [ "$sig" = bad ]; then
    add 3 "Apps" "App's code signature is missing or broken" "$app" "codesign verification failed" \
      "The app may have been modified or is damaged. Re-download it from the developer, or delete it."
  elif [ "$gk" = rejected ]; then
    add 4 "Apps" "App is not notarized by Apple" "$app" "Gatekeeper assessment: rejected" \
      "Fine if you trust the developer. Otherwise prefer apps from the App Store or notarized downloads."
  fi
done
inv ""

status "trusted root certificates"
for dom in admin user; do
  if [ $dom = admin ]; then CT=$(tmo 15 security dump-trust-settings -d 2>&1); else CT=$(tmo 15 security dump-trust-settings 2>&1); fi
  CN=$(printf '%s\n' "$CT" | sed -n 's/^Cert [0-9]*: //p' | head -8 | paste -sd ';' -)
  [ -n "$CN" ] && add 2 "Network" "Extra trusted certificate(s) installed ($dom level)" "Keychain Access" "$CN" \
    "A custom trusted certificate lets its owner read your encrypted web traffic. Keep only ones you know (work VPN, developer tools); delete others in Keychain Access."
done

if [ $FDA = 1 ] && command -v sqlite3 >/dev/null 2>&1; then
  status "privacy permissions"
  inv "== Apps with powerful privacy permissions"
  TCCS=""
  for db in "/Library/Application Support/com.apple.TCC/TCC.db" "$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
    for svc in kTCCServiceSystemPolicyAllFiles:FullDisk kTCCServiceAccessibility:Accessibility kTCCServiceScreenCapture:ScreenRecording kTCCServiceListenEvent:InputMonitoring; do
      L=$(tmo 10 sqlite3 "$db" "select client from access where service='${svc%%:*}' and auth_value=2;" 2>/dev/null | grep -v '^com\.apple\.' | sort -u)
      [ -n "$L" ] && { inv "${svc##*:}: $(echo $L)"; TCCS="$TCCS ${svc##*:}: $(echo $L);"; }
    done
  done
  inv ""
  [ -n "$TCCS" ] && add 4 "Privacy" "Apps can read all files, record the screen or watch keystrokes" "Privacy & Security" "$TCCS" \
    "Review System Settings > Privacy & Security (Full Disk Access, Accessibility, Screen Recording, Input Monitoring) and remove anything you don't recognise."
fi
if [ $IS_ROOT = 1 ]; then
  status "background items database"
  tmo 60 sfltool dumpbtm > "$OUTDIR/background_items.txt" 2>/dev/null
fi
phase_done

# ================================================================== 5. FILE SCAN
if [ $SYSTEM_ONLY = 0 ]; then
phase "5/6" "File & secrets scan"
ROOTS=""
if [ -n "$CUSTOM_ROOTS" ]; then
  ROOTS="$CUSTOM_ROOTS"
elif [ $FULL = 1 ]; then
  ROOTS="/
"
else
  if [ $IS_ROOT = 1 ]; then
    for h in $(dscl . list /Users NFSHomeDirectory | awk '$2 ~ /^\/Users\// {print $2}'); do ROOTS="$ROOTS$h
"; done
    ROOTS="$ROOTS/private/var/root
"
  else
    ROOTS="$REAL_HOME
"
  fi
  for d in /Users/Shared /private/etc /usr/local/etc /opt/homebrew/etc /Library/LaunchAgents /Library/LaunchDaemons \
           "/Library/Application Support" /private/tmp /private/var/tmp; do
    [ -d "$d" ] && ROOTS="$ROOTS$d
"
  done
fi
meta roots "$(printf '%s' "$ROOTS" | paste -sd ',' -)"
[ "$IS_TTY" = 1 ] && printf '\r\033[K'
trap 'INTERRUPTED=1' INT
SCAN_ROOTS="$ROOTS" FINDINGS="$FINDINGS" META="$META" MAX_MB="$MAX_MB" IS_TTY="$IS_TTY" COLS="$COLS" \
NO_FDA=$((1 - FDA)) INCLUDE_CLOUD="$INCLUDE_CLOUD" OUTDIR="$OUTDIR" SELF="$SELF" perl - <<'PERL_SCAN'
use strict; use warnings;
use File::Find ();
use MIME::Base64 qw(decode_base64);
use Time::HiRes qw(time);

my @roots  = grep { length && -e } split /\n/, ($ENV{SCAN_ROOTS} // '');
my $maxb   = ($ENV{MAX_MB} || 5) * 1048576;
my $tty    = $ENV{IS_TTY} // 0;
my $nofda  = $ENV{NO_FDA} // 0;
my $cloud  = $ENV{INCLUDE_CLOUD} // 0;
my $outdir = $ENV{OUTDIR} // '';
my $self   = $ENV{SELF} // '';
my $cols   = $ENV{COLS} || 100;
open(my $F, '>>', $ENV{FINDINGS}) or die "cannot write findings: $!\n";

my %S = map { $_ => 0 } qw(files text bytes binary large cloud denied pruned sigchecked);
my (%cap, @macho, @apps, @ww, @suid);
my ($stop, $last, $nfind, $si, $TESTY) = (0, 0, 0, 0, 0);
$SIG{INT} = $SIG{TERM} = sub { $stop = 1 };
my @spin = ('|', '/', '-', '\\');

# Can other local users reach files inside each home folder?
my %home_open;
for my $h (glob('/Users/*')) { my @s = stat $h or next; $home_open{$h} = ($s[2] & 0001) ? 1 : 0 }
sub others_can_read {
  my ($f, $mode) = @_;
  return 0 unless $mode & 0004;
  if ($f =~ m{^(/Users/[^/]+)/} && exists $home_open{$1} && $1 ne '/Users/Shared') { return $home_open{$1} }
  return 1;
}

sub clean { my $s = shift // ''; $s =~ s/[\t\r\n]+/ /g; $s =~ s/[\x00-\x1f\x7f]//g; $s }
sub add { print $F join("\t", map { clean($_) } @_[0..5]), "\n"; $nfind++ }
sub report {
  my ($sev, $cat, $title, $loc, $ev, $act, $f, $mode) = @_;
  return if ++$cap{"$f|$title"} > 3 || ++$cap{"$f|*"} > 25;
  if ($TESTY && $cat eq 'Secrets') { $sev = $sev < 4 ? $sev + 1 : 4; $title .= ' (in a test/sample folder)' }
  if (defined $mode && others_can_read($f, $mode) && $f !~ m{^/(?:private/)?etc/}) {
    $sev-- if $sev > 1; $ev .= '  [other users on this Mac can read this file]';
  }
  $ev .= '  [in Trash]' if $f =~ m{/\.Trash/};
  add($sev, $cat, $title, $loc, $ev, $act);
}
sub commify { my $n = reverse shift; $n =~ s/(\d{3})(?=\d)/$1,/g; scalar reverse $n }
sub human { my $b = shift; for my $u ('B','KB','MB','GB') { return sprintf('%.1f %s', $b, $u) if $b < 1024; $b /= 1024 } sprintf('%.1f TB', $b) }
sub progress {
  return unless $tty; my $now = time; return if $now - $last < 0.12; $last = $now;
  my ($label, $p) = @_;
  my $pre = sprintf("  %s %s  %s files  %s  %d findings  ", $spin[$si++ % @spin], $label, commify($S{files}), human($S{bytes}), $nfind);
  my $room = $cols - length($pre) - 2; $room = 0 if $room < 0;
  $p = length($p) > $room ? ($room > 3 ? '...' . substr($p, -($room - 3)) : '') : $p;
  print STDERR "\r\e[K\e[36m$pre\e[0m\e[2m$p\e[0m";
}

# ---------- what to skip
my $PRUNE_NAME = qr/^(?:\.git|\.hg|\.svn|node_modules|bower_components|\.npm|\.yarn|\.pnpm-store|\.cache|__pycache__|\.venv|venv|site-packages|dist-packages|\.tox|\.mypy_cache|\.pytest_cache|Pods|DerivedData|\.gradle|\.m2|\.cargo|\.rustup|\.gem|\.cpan|\.cocoapods|\.nvm|\.pyenv|\.rbenv|\.bun|\.deno|\.vscode-server|\.vscode|\.cursor|\.windsurf|\.android|miniconda3|anaconda3|miniforge3|Caches|Cache|Code Cache|GPUCache|CacheStorage|Service Worker|IndexedDB|blob_storage|Crashpad|ShaderCache|GrShaderCache|\.Spotlight-V100|\.fseventsd|\.DocumentRevisions-V100|\.TemporaryItems|SecurityScans)$/;
my $PRUNE_SUFFIX = qr/\.(?:photoslibrary|musiclibrary|tvlibrary|imovielibrary|fcpbundle|aplibrary|app|framework|xcarchive|bundle|plugin|kext|appex|sparsebundle|vmwarevm|pvm|utm|xcassets|xcframework|dSYM|lproj)$/i;
my $PRUNE_ABS = qr{^/(?:System|Volumes|dev|cores|nix|private/var/(?:db|folders|vm|protected|networkd|log|run|containers)|usr/(?:bin|sbin|lib|libexec|share|standalone)|bin|sbin|Applications|Library/(?:Caches|Developer|Apple|Updates|Logs|Frameworks|Extensions|Fonts|Audio|Printers|Components|Speech|Ruby|Perl|Python|Java|Filesystems|QuickLook|Spotlight|Screen Savers|Desktop Pictures|Image Capture|Documentation|Bluetooth|Keychains|Application Support/(?:Apple|com\.apple\.[^/]*|CrashReporter))|opt/homebrew/(?:Cellar|Caskroom|Library|share|lib|include|var/homebrew)|usr/local/(?:Cellar|Caskroom|Homebrew|share|lib|include))$};
my $HOME_LIB_KEEP = qr/^(?:LaunchAgents|Application Support|Autosave Information)$/;
my $APPSUP_PRUNE = qr{/Library/Application Support/(?:Google|BraveSoftware|Microsoft Edge|Microsoft|Firefox|Arc|Vivaldi|Opera[^/]*|Chromium|Slack|discord|Spotify|Steam|MobileSync|CallHistory\w*|AddressBook|Knowledge|FileProvider|CloudDocs|com\.apple\.[^/]+|Apple|CrashReporter|zoom\.us|WhatsApp|Telegram Desktop|Signal|Docker|OrbStack|Adobe|Mozilla|Code/(?:Cache\w*|CachedData|CachedExtensionVSIXs|User/workspaceStorage|User/globalStorage|logs)|Cursor/(?:Cache\w*|CachedData|User/workspaceStorage|User/globalStorage|logs)|Claude/(?:Cache|Code Cache|vm_bundles))$};
my $SKIP_EXT = qr/\.(?:jpe?g|png|gif|heic|heif|webp|tiff?|bmp|ico|icns|psd|ai|sketch|fig|raw|cr2|cr3|nef|arw|dng|mp3|m4a|m4b|aac|wav|flac|aiff?|ogg|opus|mp4|m4v|mov|avi|mkv|webm|wmv|zip|gz|tgz|bz2|xz|zst|7z|rar|tar|dmg|iso|img|pkg|mpkg|pdf|docx?|xlsx?|pptx?|pages|numbers|odt|ods|odp|epub|mobi|woff2?|ttf|otf|eot|dylib|so|a|o|obj|class|jar|war|pyc|pyo|wasm|node|sqlite3?|db|db-wal|db-shm|realm|car|nib|metallib|bin|pak|asar|map|ipa|apk|aab|exe|dll|msi|vmdk|qcow2|vdi|swp|emlx|mbox|icloud|lock|DS_Store)$|\.min\.(?:js|css)$|\.(?:bundle|chunk)\.js$/i;

sub prune_dir {
  my ($p, $e) = @_;
  return 1 if $outdir && $p eq $outdir;
  return 1 if $e =~ $PRUNE_NAME;
  return 1 if $e =~ $PRUNE_SUFFIX;
  return 1 if $p =~ $PRUNE_ABS;
  if ($p =~ m{^/(?:Users/[^/]+|private/var/root)/Library/([^/]+)$}) {
    my $d = $1;
    return 0 if $d =~ $HOME_LIB_KEEP;
    return 0 if $cloud && $d =~ /^(?:Mobile Documents|CloudStorage)$/;
    return 1;
  }
  return 1 if $p =~ m{^/Users/[^/]+/(?:Pictures|Music|Movies|Applications)$};
  return 1 if $p =~ m{/go/pkg$};
  return 1 if $p =~ $APPSUP_PRUNE;
  return 1 if $nofda && $p =~ m{^/Users/[^/]+/(?:Desktop|Documents|Downloads)$};
  return 0;
}

sub check_git_config {
  my $cfg = shift;
  open(my $fh, '<', $cfg) or return; local $/; my $c = <$fh>; close $fh; return unless defined $c;
  while ($c =~ m{url\s*=\s*(\S+?://[^\s:/@]+:([^\s@]+)@\S+)}g) {
    my ($url, $pw) = ($1, $2);
    (my $ev = $url) =~ s/\Q$pw\E/mask($pw)/e;
    add(1, 'Secrets', 'Git remote URL contains a password or token', $cfg, $ev,
        'Revoke the token on GitHub/GitLab, then run: git remote set-url origin https://<host>/<repo>.git  and use a credential helper (git config --global credential.helper osxkeychain).');
  }
}

sub pre {
  return () if $stop;
  my $dir = $File::Find::dir;
  my @keep;
  for my $e (@_) {
    next if $e eq '.' || $e eq '..';
    my $p = $dir eq '/' ? "/$e" : "$dir/$e";
    if (!-l $p && -d _) {
      if ($e eq '.git') { check_git_config("$p/config") }
      if (prune_dir($p, $e)) {
        push @apps, $p if $e =~ /\.app$/i && $p !~ m{^/Applications/} && $p =~ m{/(?:Downloads|Desktop|Documents|Shared)/[^/]+\.app$} && @apps < 40;
        $S{pruned}++; next;
      }
    }
    push @keep, $e;
  }
  return @keep;
}

# ---------- secret detection
my $PH = qr/^(?:x{3,}|\*+|\.{3,}|0{6,}|1234\d*|password\d*|passw0rd|secret|changeme|change_?me|example|sample|dummy|test(?:ing)?|fake|demo|foo|bar|foobar|baz|abc123|qwerty|null|none|nil|undefined|true|false|yes|no|redacted|placeholder|todo|tbd|n\/?a|admin|root|user(?:name)?|pass|your.*|my.*|enter.*|insert.*|replace.*|<.*>|\[.*\]|\{.*\}|\$.*|%.*%|#.*|\(.*\)|@.*)$/i;
sub is_placeholder {
  my $v = shift; return 1 unless defined $v && length $v;
  return 1 if $v =~ $PH;
  return 1 if $v =~ /example|placeholder|dummy|sample|xxxxx|\*\*\*|process\.env|os\.environ|getenv|ENV\[|\$\{|\{\{|<%|%\(|\bnull\b|^\$|^%|\.\.\./i;
  return 1 if $v =~ /^(.)\1+$/;
  return 0;
}
sub entropy { my $s = shift; my %c; $c{$_}++ for split //, $s; my ($e, $l) = (0, length $s); for (values %c) { my $p = $_ / $l; $e -= $p * log($p) / log(2) } $e }
sub mask { my $s = shift; my $l = length $s; return '*' x $l if $l <= 6; my $k = $l >= 16 ? 4 : 2; substr($s, 0, $k) . ('*' x 8) . substr($s, -2) }
sub mask_pw { my $s = shift; substr($s, 0, 1) . '*******' . ' (' . length($s) . ' chars)' }
sub luhn { my $n = shift; my ($sum, $alt) = (0, 0); for my $d (reverse split //, $n) { if ($alt) { $d *= 2; $d -= 9 if $d > 9 } $sum += $d; $alt = !$alt } $sum % 10 == 0 }

my %ACT = (
  token => 'Revoke or rotate this key in the provider\'s dashboard, then delete it from the file (and from git history if it was ever committed). Keep secrets in a password manager or the macOS Keychain.',
  pw    => 'Change this password, then delete it from the file. Keep passwords in a password manager (Apple Passwords, 1Password, Bitwarden).',
  hist  => 'Change the exposed password/token, then remove that line from your shell history file (open it in a text editor) so it is not stored in plain text.',
  env   => 'Fine for local development if the file never leaves this Mac. Never commit it to git or share it; rotate the value if it was ever exposed.',
);

my @RULES = (
  { sev=>1, t=>'AWS secret access key', re=>qr/aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9\/+]{40})(?![A-Za-z0-9\/+])/i },
  { sev=>2, t=>'AWS access key ID', re=>qr/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/ },
  { sev=>1, t=>'GitHub access token', re=>qr/\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/ },
  { sev=>1, t=>'GitHub fine-grained token', re=>qr/\b(github_pat_[A-Za-z0-9_]{60,255})\b/ },
  { sev=>1, t=>'GitLab access token', re=>qr/\b(glpat-[A-Za-z0-9_\-]{20,})/ },
  { sev=>2, t=>'Slack token', re=>qr/\b(xox[abposr]-[A-Za-z0-9-]{10,})/ },
  { sev=>2, t=>'Slack webhook URL', re=>qr{https://hooks\.slack\.com/services/(T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)} },
  { sev=>2, t=>'Discord webhook URL', re=>qr{https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+/[A-Za-z0-9_\-]+)} },
  { sev=>2, t=>'Telegram bot token', re=>qr/\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b/ },
  { sev=>2, t=>'Google API key', re=>qr/\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])/ },
  { sev=>1, t=>'Google OAuth client secret', re=>qr/\b(GOCSPX-[A-Za-z0-9_\-]{28})/ },
  { sev=>1, t=>'Stripe live secret key', re=>qr/\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})/ },
  { sev=>4, t=>'Stripe test key', re=>qr/\b(sk_test_[0-9a-zA-Z]{20,})/ },
  { sev=>1, t=>'OpenAI API key', re=>qr/\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,})/ },
  { sev=>1, t=>'OpenAI API key', re=>qr/\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,})/ },
  { sev=>1, t=>'Anthropic API key', re=>qr/\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})/ },
  { sev=>2, t=>'Hugging Face token', re=>qr/\b(hf_[A-Za-z]{34})\b/ },
  { sev=>1, t=>'SendGrid API key', re=>qr/\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})/ },
  { sev=>2, t=>'Twilio API key', re=>qr/\b(SK[0-9a-fA-F]{32})\b/, ctx=>qr/twilio/i },
  { sev=>2, t=>'Mailgun API key', re=>qr/\b(key-[0-9a-f]{32})\b/, ctx=>qr/mailgun/i },
  { sev=>1, t=>'npm access token', re=>qr/\b(npm_[A-Za-z0-9]{36})\b/ },
  { sev=>1, t=>'npm auth token (.npmrc)', re=>qr/_auth(?:Token)?\s*=\s*["']?([^\s"'\$]{16,})/ },
  { sev=>1, t=>'PyPI upload token', re=>qr/\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})/ },
  { sev=>1, t=>'Docker Hub access token', re=>qr/\b(dckr_pat_[A-Za-z0-9_\-]{27,})/ },
  { sev=>2, t=>'Docker registry password saved in plain text', re=>qr/"auth"\s*:\s*"([A-Za-z0-9+\/=]{12,})"/, path=>qr{/\.docker/config\.json$} },
  { sev=>1, t=>'DigitalOcean token', re=>qr/\b(do[opr]_v1_[a-f0-9]{64})\b/ },
  { sev=>1, t=>'Shopify access token', re=>qr/\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b/ },
  { sev=>1, t=>'Azure storage account key', re=>qr/AccountKey=([A-Za-z0-9+\/=]{86,88})/ },
  { sev=>2, t=>'Mapbox secret token', re=>qr/\b(sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})/ },
  { sev=>1, t=>'Database connection string with password', pw=>1, url=>1,
    re=>qr{\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s:/@'"<>]+:([^\s@'"<>/]{3,})@[\w.\-\[\]:]+}i },
  { sev=>2, t=>'Password embedded in a URL', pw=>1, url=>1,
    re=>qr{\b(?:https?|ftps?|sftp|smb|afp|ssh|git|ldaps?)://[^\s:/@'"<>]+:([^\s@'"<>/]{3,})@[\w.\-\[\]:]+}i },
  { sev=>2, t=>'Bearer token in a request header', re=>qr/Authorization["']?\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9\-._~+\/]{20,}=*)/i },
  { sev=>3, t=>'Login/session token (JWT)', re=>qr/\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})/ },
  # passwords typed on the command line (history, scripts)
  { sev=>2, t=>'Password typed on a command line', pw=>1, scope=>'env', re=>qr/sshpass\s+-p\s*["']?([^\s"']{3,})/ },
  { sev=>2, t=>'Password typed on a command line', pw=>1, scope=>'env', re=>qr/\bmysql(?:dump|admin)?\b[^\n]*?\s-p([^\s"'\-][^\s"']{2,})/ },
  { sev=>2, t=>'Password typed on a command line', pw=>1, scope=>'env', re=>qr/echo\s+["']?([^\s"'|]{3,})["']?\s*\|\s*sudo\s+-S/ },
  { sev=>2, t=>'Password typed on a command line', pw=>1, scope=>'env', re=>qr/\bcurl\b[^\n]*?\s(?:-u|--user)\s*["']?[^:\s"']+:([^\s"']{3,})/ },
  { sev=>2, t=>'Secret stored in an environment/config variable', pw=>1, scope=>'env', notest=>1, a=>'env', generic=>1,
    re=>qr/^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]{0,40}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|APIKEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)[A-Za-z0-9_]{0,40}[ \t]*=[ \t]*["']?([^\s"'#\$]{6,200})/im },
  { sev=>3, t=>'Hard-coded password or secret in code/config', pw=>1, scope=>'conf', notest=>1, ent=>3.0, generic=>1,
    re=>qr/(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)[\w.\-]{0,30}["']?\s*(?:[:=]|=>|:=)\s*["']([^"'\s]{8,200})["']/i },
  # passwords written down in notes / text documents (English + Arabic)
  { sev=>2, t=>'Password written in a plain-text note', pw=>1, scope=>'doc', notest=>1, a=>'pw',
    re=>qr/(?:^|[\s,;(\[|])(?:password|passwd|passcode|pass|pwd|pw|pin|كلمة السر|كلمة المرور|الباسورد|باسورد|الرقم السري)\s*(?:[:=\-]|is\b)\s*(\S{4,64})/im },
  # shell startup files that run downloaded / obfuscated code
  { sev=>1, t=>'Shell startup file runs downloaded or obfuscated code', cat=>'Persistence', scope=>'rc', raw=>1,
    a=>'If you did not add this line yourself, delete it from the file, then run a malware scan.',
    re=>qr/((?:curl|wget)[^\n|]{0,200}\|\s*(?:ba|z)?sh\b|base64\s+(?:-d|--decode|-D)[^\n]*\|\s*(?:ba|z)?sh|\/dev\/tcp\/[\d.]+\/\d+|\bnc\s+-e\s)/ },
);

my $DOC_EXT = qr/\.(?:txt|text|md|markdown|rtf|csv|tsv|log|note|notes|org)$/i;
my $HIST    = qr/^\.(?:zsh_history|bash_history|sh_history|python_history|mysql_history|psql_history|node_repl_history|sqlite_history|irb_history|rediscli_history|history)$/;
my $RC      = qr/^\.(?:zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|profile|netrc|pgpass|git-credentials|npmrc|pypirc|s3cfg|boto|my\.cnf)$/;
my $NOEXT_CODE = qr/^(?:Makefile|Dockerfile|Gemfile|Rakefile|Podfile|Procfile|Vagrantfile|Brewfile|LICENSE|README|CHANGELOG|AUTHORS|COPYING|NOTICE|CODEOWNERS)$/i;
my %TESTCARDS = map { $_ => 1 } qw(4111111111111111 4242424242424242 5555555555554444 4012888888881881 378282246310005 371449635398431 5105105105105100 4000056655665556 6011111111111117 4000000000000002 5200828282828210);

sub scan_content {
  my ($f, $n, $c, $mode) = @_;
  my $ishist = ($n =~ $HIST || $f =~ m{/\.zsh_sessions/}) ? 1 : 0;
  my $isrc   = $n =~ $RC ? 1 : 0;
  my $isdoc  = (!$ishist && !$isrc && ($n =~ $DOC_EXT || ($n !~ /\./ && $n !~ $NOEXT_CODE))) ? 1 : 0;
  my $isconf = $isdoc ? 0 : 1;
  my $isenv  = ($ishist || $isrc || $n =~ /^\.env/i || $n =~ /\.(?:env|ini|cfg|conf|properties|sh|bash|zsh|command|tfvars)$/i) ? 1 : 0;
  my $hact   = $ishist ? $ACT{hist} : undef;

  # Google Cloud service-account key file
  my $svc = 0;
  if (index($$c, 'service_account') >= 0 && $$c =~ /"type"\s*:\s*"service_account"/ && $$c =~ /"private_key"\s*:\s*"-----BEGIN/) {
    $svc = 1;
    report(1, 'Secrets', 'Google Cloud service-account key file', $f, 'service_account JSON with an embedded private key',
      'If unused, delete the key in Google Cloud Console (IAM > Service Accounts > Keys). Otherwise keep it out of shared folders and git, and rotate it regularly.', $f, $mode);
  }

  # Private keys (SSH, TLS, PGP)
  if (!$svc && index($$c, 'PRIVATE KEY') >= 0) {
    pos($$c) = undef; my $k = 0;
    while ($$c =~ /-----BEGIN ((?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----(.{0,20000}?)-----END/sg) {
      my ($type, $body, $pos) = ($1, $2, $-[0]);
      my $enc = 0;
      if ($type =~ /ENCRYPTED|PGP/ || $body =~ /Proc-Type:\s*4,ENCRYPTED/) { $enc = 1 }
      elsif ($type =~ /OPENSSH/) {
        (my $b = $body) =~ s/[^A-Za-z0-9+\/=]//g;
        my $d = decode_base64($b);
        if (length($d) > 19 && substr($d, 0, 15) eq "openssh-key-v1\0") {
          my $len = unpack('N', substr($d, 15, 4));
          $enc = substr($d, 19, $len) ne 'none' ? 1 : 0;
        }
      }
      my $ln = 1 + (substr($$c, 0, $pos) =~ tr/\n//);
      my $inssh = $f =~ m{/\.ssh/} ? 1 : 0;
      if (!$enc && $inssh) {
        report(2, 'Secrets', 'SSH private key has no passphrase', "$f:$ln", "$type (unencrypted)",
          "Add a passphrase: ssh-keygen -p -f \"$f\"  - then ssh-add --apple-use-keychain so macOS remembers it.", $f, $mode);
      } elsif (!$enc) {
        report(1, 'Secrets', 'Unencrypted private key stored outside ~/.ssh', "$f:$ln", "$type (unencrypted)",
          'If still needed, move it to ~/.ssh (chmod 600) and add a passphrase. If it was ever shared, emailed or committed, replace it with a new key.', $f, $mode);
      } elsif (!$inssh) {
        report(4, 'Secrets', 'Passphrase-protected private key found', "$f:$ln", $type,
          'Fine if expected. Delete it if no longer needed.', $f, $mode);
      }
      if ($inssh && ($mode & 0077)) {
        add(2, 'Files', 'Private key file can be read by other users', $f, sprintf('permissions %o', $mode & 07777), "Run: chmod 600 \"$f\"");
      }
      last if ++$k >= 3;
    }
  }

  # Pattern rules (generic rules skip lines already reported by a specific rule)
  my %done;
  for my $r (@RULES) {
    my $scope = $r->{scope} // 'all';
    next if $scope eq 'doc'  && !$isdoc;
    next if $scope eq 'conf' && !$isconf;
    next if $scope eq 'env'  && !$isenv;
    next if $scope eq 'rc'   && !$isrc;
    next if $r->{notest} && $TESTY;
    next if $r->{ctx}  && $$c !~ $r->{ctx};
    next if $r->{path} && $f !~ $r->{path};
    pos($$c) = undef; my $hits = 0;
    while ($$c =~ /$r->{re}/g) {
      my ($ms, $me, $ss, $se) = ($-[0], $+[0], $-[1], $+[1]);
      my $secret = $1;
      next if !$r->{raw} && is_placeholder($secret);
      next if $r->{ent} && entropy($secret) < $r->{ent};
      my $ev = substr($$c, $ms, $me - $ms);
      substr($ev, $ss - $ms, $se - $ss) = $r->{pw} ? mask_pw($secret) : mask($secret) unless $r->{raw};
      $ev =~ s/\s+/ /g; $ev = substr($ev, 0, 160) . '...' if length $ev > 160;
      my $ln = 1 + (substr($$c, 0, $ms) =~ tr/\n//);
      next if $r->{generic} && $done{$ln};
      $done{$ln} = 1;
      my ($sev, $title) = ($r->{sev}, $r->{t});
      if ($r->{url} && $ev =~ /@(?:localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal|(?:db|database|postgres|mysql|redis|mongo|rabbitmq)\b)/i) {
        ($sev, $title) = (4, "$title (local development)");
      }
      $sev = 1 if $n eq '.git-credentials' && $sev > 1;
      my $act = $hact // ($r->{a} ? ($ACT{$r->{a}} // $r->{a}) : $ACT{token});
      report($sev, $r->{cat} // 'Secrets', $title, "$f:$ln", $ev, $act, $f, $mode);
      last if ++$hits >= 3;
    }
  }

  return unless $isdoc && !$TESTY;

  # Payment card numbers (Luhn-validated)
  if ($$c =~ /\d{4}/) {
    pos($$c) = undef; my $h = 0;
    while ($$c =~ /(?<![\d\-])((?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6011)(?:[ \-]?\d{4}){2}[ \-]?\d{1,7})(?![\d\-])/g) {
      my $pos = $-[0]; (my $d = $1) =~ s/\D//g;
      next unless length($d) >= 13 && length($d) <= 19 && luhn($d);
      next if $TESTCARDS{$d} || $d =~ /^(\d)\1+$/;
      my $ln = 1 + (substr($$c, 0, $pos) =~ tr/\n//);
      report(2, 'Secrets', 'Possible payment card number', "$f:$ln", substr($d, 0, 4) . ' **** **** ' . substr($d, -4),
        'If this is a real card, delete the file (and empty the Trash) or move the details into a password manager.', $f, $mode);
      last if ++$h >= 3;
    }
  }
  # US Social Security numbers (only when the file mentions SSN)
  if ($$c =~ /\b(?:ssn|social security)\b/i) {
    pos($$c) = undef;
    while ($$c =~ /\b((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b/g) {
      my $ln = 1 + (substr($$c, 0, $-[0]) =~ tr/\n//);
      report(3, 'Secrets', 'Possible Social Security number', "$f:$ln", '***-**-' . substr($1, -4),
        'Delete or encrypt documents containing ID numbers you no longer need.', $f, $mode);
      last;
    }
  }
  # Crypto wallet recovery (seed) phrases: a line of exactly 12 or 24 lowercase words
  if ($$c =~ /\b(?:seed|mnemonic|recovery phrase|secret phrase|secret recovery|wallet|metamask|ledger|trezor|bitcoin|ethereum|crypto|phantom|exodus|trust wallet)\b/i) {
    pos($$c) = undef;
    while ($$c =~ /^[ \t]*(?:\d+[.)][ \t]*)?((?:[a-z]{3,8}[ \t]+){11}[a-z]{3,8}(?:(?:[ \t]+[a-z]{3,8}){12})?)[ \t]*\r?$/mg) {
      my $p = $1; my $pos = $-[0]; my @w = split /\s+/, $p;
      next unless @w == 12 || @w == 24;
      next if $p =~ /\b(?:the|and|you|are|was|for|with|this|that|have|not|but|from|they|our|your|will|can|has|had|its|his|her|she|him|who|how|what|when|why|all|any)\b/;
      my %u; $u{$_}++ for @w; next if keys(%u) < 9;
      my $ln = 1 + (substr($$c, 0, $pos) =~ tr/\n//);
      report(1, 'Secrets', 'Possible crypto wallet recovery (seed) phrase', "$f:$ln", "$w[0] **** **** (" . scalar(@w) . ' words)',
        'Anyone with this phrase can take your crypto. Move the funds to a new wallet with a new phrase, keep the phrase on paper/steel offline, and delete this file.', $f, $mode);
      last;
    }
  }
}

sub name_rules {
  my ($f, $n, $mode, $size) = @_;
  if ($n =~ /\.(?:p12|pfx)$/i) {
    report(3, 'Secrets', 'Certificate bundle with a private key (.p12/.pfx)', $f, "$size bytes",
      'Keep it only if needed, protected by a strong password; otherwise delete it.', $f, $mode);
  } elsif ($n eq 'wallet.dat' || $n =~ /^UTC--\d{4}-\d\d-\d\dT/ || $n =~ /\.(?:wallet|keystore)$/i) {
    report(2, 'Secrets', 'Cryptocurrency wallet / keystore file', $f, "$size bytes",
      'Wallet files are a top target for Mac info-stealers. Keep funds on a hardware wallet, keep encrypted offline backups and delete stray copies.', $f, $mode);
  } elsif (!$TESTY
      && $n =~ /\.(?:txt|rtf|md|csv|tsv|xlsx?|numbers|docx?|pages|pdf|odt|ods)$/i
      && $n =~ /(?:^|[^a-z])(?:passwords?|passwds?|passcodes?|credentials?|logins?|secrets?|recovery[ _\-]?(?:keys?|codes?|phrase)|seed[ _\-]?phrase|mnemonic|backup[ _\-]?codes?|2fa|mfa|كلمات السر|كلمة السر|باسورد)(?:[^a-z]|$)/i) {
    report(2, 'Secrets', 'Document whose name suggests it stores passwords or recovery codes', $f, "$size bytes",
      'Move the contents into a password manager (Apple Passwords, 1Password, Bitwarden), then delete the file and empty the Trash.', $f, $mode);
  }
}

sub wanted {
  return if $stop;
  my $f = $File::Find::name;
  my @s = lstat $f; return unless @s && -f _;
  my ($mode, $size, $blocks) = @s[2, 7, 12];
  $S{files}++;
  progress('Scanning files', $f);
  return if $f eq $self;
  (my $n = $f) =~ s{.*/}{};
  $TESTY = $f =~ m{/(?:tests?|spec|specs|__tests__|__mocks__|fixtures?|examples?|samples?|testdata|test-data|mocks?|vendor|third[_\-]party|docs?)/}i ? 1 : 0;
  push @suid, $f if ($mode & 06000) && @suid < 50;
  push @ww, $f if ($mode & 0002) && $f !~ m{^/private/(?:tmp|var/tmp)/} && @ww < 500;
  name_rules($f, $n, $mode, $size);
  return if $size == 0;
  if ($blocks == 0) { $S{cloud}++; return }            # iCloud/Dropbox placeholder - don't trigger a download
  if ($size > $maxb) { $S{large}++; return }
  my $skipext = $n =~ $SKIP_EXT ? 1 : 0;
  return if $skipext && !($mode & 0111);
  open(my $fh, '<:raw', $f) or do { $S{denied}++; return };
  my $head = ''; read($fh, $head, 8192);
  if ($head =~ /^(?:\xcf\xfa\xed\xfe|\xce\xfa\xed\xfe|\xca\xfe\xba\xbe)/) {
    push @macho, $f if ($mode & 0111) && @macho < 3000;
    close $fh; $S{binary}++; return;
  }
  if ($skipext || index($head, "\0") >= 0) { close $fh; $S{binary}++; return }
  my $rest = do { local $/; <$fh> }; close $fh;
  my $c = defined $rest ? $head . $rest : $head;
  $S{text}++; $S{bytes} += length $c;
  scan_content($f, $n, \$c, $mode);
}

local $SIG{__WARN__} = sub { $S{denied}++ };
for my $root (@roots) {
  last if $stop;
  File::Find::find({ wanted => \&wanted, preprocess => \&pre, no_chdir => 1 }, $root);
}

# ---------- unsigned programs
sub exe_risk {
  my $f = shift; (my $n = $f) =~ s{.*/}{};
  return 'high' if $n =~ /^\./;
  return 'high' if $f =~ m{^/(?:private/)?(?:tmp|var/tmp)/} || $f =~ m{^/Users/Shared/}
                || $f =~ m{^/Users/[^/]+/(?:Downloads|Desktop|Documents|Public)/} || $f =~ m{/Library/(?:Caches|LaunchAgents)/};
  return 'med'  if $f =~ m{^/Users/[^/]+/\.(?!local/|config/|docker/|orbstack/|colima/|lima/|asdf/|sdkman/|oh-my-zsh/|Trash/)[^/]+/};
  return 'med'  if $f =~ m{/Library/Application Support/\.[^/]+/};
  return 'low';
}
my %ord = (high => 0, med => 1, low => 2);
my @cand = sort { $ord{$a->[1]} <=> $ord{$b->[1]} } map { [$_, exe_risk($_)] } @macho;
my ($nlow, $lowchk, @lowex) = (0, 0);
for my $x (@cand) {
  last if $stop;
  my ($f, $risk) = @$x;
  next if $risk eq 'low' && $lowchk++ >= 200;
  $S{sigchecked}++;
  progress('Checking program signatures', $f);
  my $info  = `codesign -dv \Q$f\E 2>&1`;
  my $valid = system("codesign -v \Q$f\E >/dev/null 2>&1") == 0;
  my $adhoc = $info =~ /Signature=adhoc/ ? 1 : 0;
  next if $valid && !$adhoc;
  my $what = !$valid ? ($info =~ /not signed at all/ ? 'not signed' : 'signature invalid') : 'ad-hoc signed (no developer identity)';
  if ($risk eq 'high') {
    add(2, 'Malware', 'Unsigned program in a risky location', $f, $what,
      'Programs without a developer signature in Downloads, shared, temp or hidden locations are a common malware sign. If you do not know what it is, delete it and run a malware scan.');
  } elsif ($risk eq 'med') {
    add(3, 'Malware', 'Unsigned program inside a hidden folder', $f, $what, 'Usually a developer tool. Delete it if you do not recognise it.');
  } else { $nlow++; push @lowex, $f if @lowex < 8 }
}
add(4, 'Files', "Unsigned programs in your folders ($nlow)", join('; ', @lowex), 'usually self-built or developer tools',
  'Normal for developer tools. Remove any you do not recognise.') if $nlow;

for my $app (@apps) {
  last if $stop;
  progress('Checking downloaded apps', $app);
  my $ok = system("codesign -v \Q$app\E >/dev/null 2>&1") == 0 && system("spctl -a -t exec \Q$app\E >/dev/null 2>&1") == 0;
  add(3, 'Apps', 'Downloaded app is unsigned or not notarized', $app, 'Gatekeeper/codesign check failed',
    'Delete it unless you are sure it is safe. Download apps only from the App Store or the developer\'s website.') unless $ok;
}
for my $f (@suid) {
  next if $f =~ m{^/(?:usr/(?:bin|sbin|libexec|lib)|bin|sbin|System|Library/Apple|Applications)/};
  add(2, 'Files', 'Program runs with elevated (set-UID/GID) rights outside system folders', $f, sprintf('mode %o', (lstat $f)[2] & 07777),
    "If you don't recognise it, remove the bit: sudo chmod u-s,g-s \"$f\"");
}
add(3, 'Files', 'Files that any user on this Mac can modify (' . scalar(@ww) . ')', join('; ', @ww[0 .. ($#ww < 7 ? $#ww : 7)]), 'world-writable',
  'Remove the permission: chmod o-w <file>. Writable scripts or configs can be tampered with by other users or malware.') if @ww;

print STDERR "\r\e[K" if $tty;
if (open(my $m, '>>', $ENV{META})) {
  print $m "$_=$S{$_}\n" for sort keys %S;
  print $m "interrupted=1\n" if $stop;
  close $m;
}
PERL_SCAN
trap - INT
grep -q '^interrupted=1' "$META" && INTERRUPTED=1
phase_done
fi

# ================================================================== 6. LOGS
if [ $INTERRUPTED = 0 ]; then
phase "6/6" "Security logs (last 3 days)"
status "reading the system log (up to 2 min)"
LOG=$(tmo 120 log show --last 3d --style compact --predicate \
  '(process == "sshd" AND eventMessage CONTAINS "Failed") OR (process == "sudo" AND eventMessage CONTAINS "incorrect password") OR (process == "screensharingd" AND eventMessage CONTAINS[c] "authentication") OR (process BEGINSWITH "XProtect" AND eventMessage CONTAINS[c] "detect") OR (process == "syspolicyd" AND eventMessage CONTAINS[c] "malware")' 2>/dev/null)
N_SSH=$(printf '%s\n' "$LOG" | grep -c 'sshd.*Failed')
N_SUDO=$(printf '%s\n' "$LOG" | grep -c 'sudo.*incorrect password')
N_VNC=$(printf '%s\n' "$LOG" | grep -ci 'screensharingd.*authentication fail')
MAL=$(printf '%s\n' "$LOG" | grep -iE 'XProtect.*detect|syspolicyd.*malware' | grep -viE 'no (threat|detection)|clean' | tail -3 | cut -c1-220 | paste -sd ';' -)
[ "$N_SSH" -gt 5 ] && add 2 "Logs" "Failed SSH logins ($N_SSH in 3 days)" "system log" "sshd authentication failures" \
  "Someone is trying to log in remotely. Turn off Remote Login, or allow only key-based logins."
[ "$N_VNC" -gt 3 ] && add 2 "Logs" "Failed Screen Sharing logins ($N_VNC in 3 days)" "system log" "screensharingd authentication failures" \
  "Turn off Screen Sharing/Remote Management if you don't use it."
[ "$N_SUDO" -gt 5 ] && add 3 "Logs" "Repeated wrong admin passwords in Terminal ($N_SUDO)" "system log" "sudo: incorrect password" "Make sure these attempts were you."
[ -n "$MAL" ] && add 1 "Malware" "macOS malware protection logged a detection" "system log" "$MAL" \
  "Run a full scan with Malwarebytes, update macOS, and change important passwords from another device."
PAN=$(ls /Library/Logs/DiagnosticReports/*.panic /Library/Logs/DiagnosticReports/Retired/*.panic 2>/dev/null | wc -l | tr -d ' ')
[ "${PAN:-0}" -gt 0 ] && add 4 "System" "The Mac has crashed (kernel panic) recently ($PAN reports)" "/Library/Logs/DiagnosticReports" "panic reports" \
  "Often caused by third-party drivers or failing hardware. Update macOS and remove old drivers; run Apple Diagnostics if it repeats."
phase_done
fi

# ================================================================== REPORT
meta duration "$(( $(date +%s) - START_TS ))"
[ $INTERRUPTED = 1 ] && printf '\n  %sScan stopped early - building a partial report.%s\n' "$YEL" "$R"
FINDINGS="$FINDINGS" META="$META" OUTDIR="$OUTDIR" INVENTORY="$INVENTORY" IS_TTY="$IS_TTY" COLS="$COLS" perl - <<'PERL_REPORT'
use strict; use warnings;
my ($FIND, $META, $OUT, $INV) = @ENV{qw(FINDINGS META OUTDIR INVENTORY)};
my $tty = $ENV{IS_TTY}; my $cols = $ENV{COLS} || 100;
my %M;
if (open my $m, '<', $META) { while (<$m>) { chomp; my ($k, $v) = split /=/, $_, 2; $M{$k} = $v if defined $v } }
my $home = $M{home} // '';

my (@F, %seen);
open my $ff, '<', $FIND or die "no findings file\n";
while (<$ff>) {
  chomp; my @x = split /\t/, $_, -1; next unless @x >= 6 && $x[0] =~ /^[1-4]$/;
  next if $seen{"$x[0]|$x[2]|$x[3]"}++;
  push @F, { sev => $x[0], cat => $x[1], title => $x[2], loc => $x[3], ev => $x[4], act => $x[5] };
}
close $ff;

my (%G, @groups);
for my $f (@F) {
  my $k = "$f->{sev}|$f->{title}";
  unless ($G{$k}) { $G{$k} = { sev => $f->{sev}, cat => $f->{cat}, title => $f->{title}, act => $f->{act}, items => [] }; push @groups, $G{$k} }
  push @{ $G{$k}{items} }, $f;
}
@groups = sort { $a->{sev} <=> $b->{sev} || @{ $b->{items} } <=> @{ $a->{items} } || $a->{title} cmp $b->{title} } @groups;
for my $g (@groups) {
  $g->{items} = [ sort { $a->{loc} cmp $b->{loc} } @{ $g->{items} } ];
  my %ac; $ac{ $_->{act} }++ for @{ $g->{items} };          # group advice = most common one
  ($g->{act}) = sort { $ac{$b} <=> $ac{$a} || ($a =~ /shell history/ ? 1 : 0) <=> ($b =~ /shell history/ ? 1 : 0) || $a cmp $b } keys %ac;
}
my %cnt; $cnt{ $_->{sev} }++ for @groups;
my %occ; $occ{ $_->{sev} }++ for @F;
my $score = 100 - 15 * ($cnt{1} // 0) - 6 * ($cnt{2} // 0) - 2 * ($cnt{3} // 0) - 0.5 * ($cnt{4} // 0);
$score = 0 if $score < 0; $score = int($score + 0.5);
my $grade = $score >= 90 ? 'A' : $score >= 80 ? 'B' : $score >= 65 ? 'C' : $score >= 50 ? 'D' : 'F';
my @SN = ('', 'Critical', 'High', 'Medium', 'Low');

sub h { my $s = shift // ''; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s =~ s/'/&#39;/g; $s }
sub tilde { my $s = shift // ''; $s =~ s/\Q$home\E/~/g if length $home; $s }
sub commify { my $n = reverse(shift // 0); $n =~ s/(\d{3})(?=\d)/$1,/g; scalar reverse $n }
sub human { my $b = shift // 0; for my $u ('B','KB','MB','GB') { return sprintf('%.1f %s', $b, $u) if $b < 1024; $b /= 1024 } sprintf('%.1f TB', $b) }
sub dur { my $s = shift // 0; sprintf('%dm %02ds', int($s / 60), $s % 60) }

# ---------- CSV
if (open my $c, '>', "$OUT/findings.csv") {
  print $c "Severity,Category,Issue,Location,Details,Recommended action\n";
  for my $f (sort { $a->{sev} <=> $b->{sev} } @F) {
    print $c join(',', map { my $v = $_ // ''; $v =~ s/"/""/g; qq("$v") } $SN[$f->{sev}], @$f{qw(cat title loc ev act)}), "\n";
  }
  close $c;
}

# ---------- HTML
my $css = <<'CSS';
:root{--bg:#f5f6f8;--card:#fff;--fg:#1f2328;--muted:#5f6b76;--line:#dde2e7;--chip:#eef1f4;--s1:#c62828;--s2:#d9480f;--s3:#a66a00;--s4:#5c6670;--ok:#1a7f37;--act:#f0f6ff;--actline:#c8dcf7}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161b22;--fg:#e6edf3;--muted:#9aa5b1;--line:#2d333b;--chip:#21262d;--s1:#ff6b6b;--s2:#ff922b;--s3:#f2c94c;--s4:#9aa5b1;--ok:#3fb950;--act:#13233a;--actline:#24456e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:34px 0 12px}.muted{color:var(--muted)}
.top{display:flex;gap:22px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}
.grade{width:92px;height:92px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;font-weight:700;flex:none}
.grade b{font-size:38px;line-height:1}.grade span{font-size:12px;opacity:.9}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;cursor:pointer;user-select:none;border-top:4px solid}
.card.off{opacity:.35}.card .n{font-size:30px;font-weight:700;line-height:1.1}.card .l{font-size:13px;color:var(--muted)}
.c1{border-top-color:var(--s1)}.c2{border-top-color:var(--s2)}.c3{border-top-color:var(--s3)}.c4{border-top-color:var(--s4)}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:999px;color:#fff;flex:none}
.b1{background:var(--s1)}.b2{background:var(--s2)}.b3{background:var(--s3)}.b4{background:var(--s4)}
.chip{font-size:12px;background:var(--chip);border-radius:999px;padding:1px 9px;color:var(--muted);flex:none}
ol.first{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px 14px 40px;margin:0}
ol.first li{margin:8px 0}ol.first .a{color:var(--muted);font-size:14px}
.tools{display:flex;gap:10px;margin:18px 0 0}.tools input{flex:1;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--fg);font-size:15px}
details.group{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:10px 0;overflow:hidden}
details.group>summary{list-style:none;cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.group>summary::-webkit-details-marker{display:none}details.group>summary .t{font-weight:600;flex:1;min-width:200px}
.body{padding:0 16px 14px}.act{background:var(--act);border:1px solid var(--actline);border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:14px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.loc{font-family:ui-monospace,Menlo,monospace;word-break:break-all;width:45%}td.ev{font-family:ui-monospace,Menlo,monospace;word-break:break-word;color:var(--muted)}
.none{color:var(--ok);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px}
dl.cov{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:0}
dl.cov dt{color:var(--muted)}dl.cov dd{margin:0;word-break:break-word}
pre{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;overflow:auto;font-size:12px;max-height:520px}
footer{margin-top:34px;font-size:13px;color:var(--muted)}
@media (max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}td.loc{width:auto}}
CSS
my $js = <<'JS';
const q=document.getElementById('q');const on=new Set(['1','2','3','4']);
function apply(){const t=q.value.trim().toLowerCase();
document.querySelectorAll('section.sev').forEach(s=>{s.style.display=on.has(s.dataset.sev)?'':'none'});
document.querySelectorAll('details.group').forEach(g=>{let any=!t||g.dataset.k.includes(t);
g.querySelectorAll('tbody tr').forEach(r=>{const m=!t||g.dataset.k.includes(t)||r.textContent.toLowerCase().includes(t);r.style.display=m?'':'none';if(m)any=true});
g.style.display=any?'':'none';if(t&&any)g.open=true})}
document.querySelectorAll('.card').forEach(c=>c.addEventListener('click',()=>{const s=c.dataset.sev;on.has(s)?on.delete(s):on.add(s);c.classList.toggle('off');apply()}));
q.addEventListener('input',apply);
JS

my $gcol = { A => 'var(--ok)', B => 'var(--ok)', C => 'var(--s3)', D => 'var(--s2)', F => 'var(--s1)' }->{$grade};
my $total = @groups;
my $verdict = !$cnt{1} && !$cnt{2} ? 'No critical or high-risk problems found.' :
              $cnt{1} ? "Found $cnt{1} critical issue(s) that need attention now." : "Found $cnt{2} high-risk issue(s) to fix soon.";
my $o = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      . "<title>Mac Security Report</title><style>$css</style></head><body><main>";
$o .= "<div class=\"top\"><div class=\"grade\" style=\"background:$gcol\"><b>$grade</b><span>$score / 100</span></div><div>"
    . "<h1>Mac Security Report</h1><div>" . h($verdict) . "</div><div class=\"muted\">" . h($M{host} // '') . " &middot; " . h($M{os} // '')
    . " &middot; " . h($M{started} // '') . " &middot; took " . dur($M{duration}) . " &middot; " . h($M{mode} // '') . "</div>"
    . ($M{interrupted} ? "<div style=\"color:var(--s2)\">Scan was stopped early - results are partial.</div>" : '') . "</div></div>";
$o .= "<div class=\"cards\">";
for my $s (1 .. 4) {
  $o .= "<div class=\"card c$s\" data-sev=\"$s\" title=\"Click to show/hide\"><div class=\"n\">" . ($cnt{$s} // 0) . "</div><div class=\"l\">$SN[$s]"
      . (($occ{$s} // 0) > ($cnt{$s} // 0) ? " &middot; $occ{$s} places" : '') . "</div></div>";
}
$o .= "</div>";
my @first = grep { $_->{sev} <= 3 } @groups;
if (@first) {
  $o .= "<h2>Fix these first</h2><ol class=\"first\">";
  for my $g (@first[0 .. ($#first < 9 ? $#first : 9)]) {
    my $n = @{ $g->{items} };
    $o .= "<li><span class=\"badge b$g->{sev}\">$SN[$g->{sev}]</span> <b>" . h($g->{title}) . "</b>" . ($n > 1 ? " <span class=\"chip\">$n places</span>" : '')
        . "<div class=\"a\">" . h($g->{act}) . "</div></li>";
  }
  $o .= "</ol>";
}
$o .= "<div class=\"tools\"><input id=\"q\" type=\"search\" placeholder=\"Filter by text, file name or category...\"></div>";
for my $s (1 .. 4) {
  my @gs = grep { $_->{sev} == $s } @groups;
  $o .= "<section class=\"sev\" data-sev=\"$s\"><h2><span class=\"badge b$s\">$SN[$s]</span> " . scalar(@gs) . " issue(s)</h2>";
  $o .= "<div class=\"none\">Nothing found at this level.</div>" unless @gs;
  for my $g (@gs) {
    my @it = @{ $g->{items} }; my $n = @it;
    my $key = lc(join ' ', $g->{title}, $g->{cat}, $SN[$s]);
    $o .= "<details class=\"group\" data-k=\"" . h($key) . "\"" . ($s <= 2 ? ' open' : '') . "><summary><span class=\"badge b$s\">$SN[$s]</span>"
        . "<span class=\"t\">" . h($g->{title}) . "</span><span class=\"chip\">" . h($g->{cat}) . "</span>" . ($n > 1 ? "<span class=\"chip\">$n</span>" : '')
        . "</summary><div class=\"body\"><div class=\"act\"><b>What to do:</b> " . h($g->{act}) . "</div><div class=\"tw\"><table><thead><tr><th>Where</th><th>Details</th></tr></thead><tbody>";
    my $shown = 0;
    for my $f (@it) {
      last if ++$shown > 300;
      my $extra = ($f->{act} ne $g->{act}) ? "<br><i>" . h($f->{act}) . "</i>" : '';
      $o .= "<tr><td class=\"loc\">" . h(tilde($f->{loc})) . "</td><td class=\"ev\">" . h(tilde($f->{ev})) . "$extra</td></tr>";
    }
    $o .= "<tr><td colspan=\"2\" class=\"muted\">... and " . ($n - 300) . " more (see findings.csv)</td></tr>" if $n > 300;
    $o .= "</tbody></table></div></div></details>";
  }
  $o .= "</section>";
}
$o .= "<h2>Scan coverage</h2><dl class=\"cov\">";
my @cov = (
  ['Files examined', commify($M{files})], ['Text files read', commify($M{text}) . ' (' . human($M{bytes}) . ')'],
  ['Skipped: binary/media', commify($M{binary})], ['Skipped: larger than limit', commify($M{large})],
  ['Skipped: cloud-only placeholders', commify($M{cloud})], ['Unreadable (permission)', commify($M{denied})],
  ['Folders skipped (caches, libraries, apps)', commify($M{pruned})], ['Program signatures checked', commify($M{sigchecked})],
  ['Full Disk Access', $M{fda}], ['Scan mode', $M{mode}], ['XProtect', $M{xprotect}], ['Folders scanned', tilde($M{roots})],
);
$o .= "<dt>" . h($_->[0]) . "</dt><dd>" . h($_->[1] // 'n/a') . "</dd>" for @cov;
$o .= "</dl>";
if (open my $iv, '<', $INV) { local $/; my $t = <$iv>; close $iv;
  $o .= "<h2>System inventory</h2><details class=\"group\"><summary><span class=\"t\">Users, startup items, apps, listening ports, privacy permissions</span></summary><pre>" . h(tilde($t)) . "</pre></details>" if $t; }
$o .= "<footer>Generated by mac_security_scan.sh. This scan is read-only and heuristic: treat findings as leads to check, not proof of compromise. "
    . "Secrets are masked in this report, but it still shows where they live - delete the folder <code>" . h(tilde($OUT)) . "</code> when you are done. "
    . "For a second opinion on malware, run a free Malwarebytes scan.</footer>";
$o .= "</main><script>$js</script></body></html>";
open my $hf, '>', "$OUT/report.html" or die "cannot write report: $!\n"; print $hf $o; close $hf;

# ---------- terminal summary
my ($B, $D, $Rs) = $tty ? ("\e[1m", "\e[2m", "\e[0m") : ('', '', '');
my @C = $tty ? ('', "\e[1;31m", "\e[1;38;5;208m", "\e[1;33m", "\e[1;37m") : ('') x 5;
my $line = '  ' . ('-' x (($cols > 70 ? 70 : $cols) - 4));
print "\n$line\n";
printf "  %sSecurity grade: %s%s (%d/100)%s   %s\n", $B, $grade, $Rs . $B, $score, $Rs, $verdict;
printf "  %s%d Critical%s   %s%d High%s   %s%d Medium%s   %s%d Low%s\n",
  $C[1], $cnt{1} // 0, $Rs, $C[2], $cnt{2} // 0, $Rs, $C[3], $cnt{3} // 0, $Rs, $C[4], $cnt{4} // 0, $Rs;
print "$line\n";
if (@first) {
  print "  ${B}Fix these first${Rs}\n";
  my $i = 0;
  for my $g (@first) {
    last if ++$i > 8;
    my $n = @{ $g->{items} };
    my $t = $g->{title} . ($n > 1 ? " ($n)" : '');
    printf "  %2d. %s%-8s%s %s\n", $i, $C[$g->{sev}], uc $SN[$g->{sev}], $Rs, $t;
    my $a = $g->{act}; my $w = $cols - 10; $w = 40 if $w < 40;
    $a = substr($a, 0, $w - 3) . '...' if length $a > $w;
    print "      $D-> $a$Rs\n";
  }
  print "$line\n";
}
printf "  Full report: %s%s/report.html%s\n", $B, tilde($OUT), $Rs;
printf "  %sAlso: findings.csv (spreadsheet), inventory.txt. Delete the folder when done.%s\n\n", $D, $Rs;
PERL_REPORT

[ $IS_ROOT = 1 ] && chown -R "$REAL_USER" "$REAL_HOME/SecurityScans" 2>/dev/null
if [ $OPEN_REPORT = 1 ] && [ -f "$OUTDIR/report.html" ]; then
  if [ $IS_ROOT = 1 ]; then command sudo -u "$REAL_USER" open "$OUTDIR/report.html" 2>/dev/null
  else open "$OUTDIR/report.html" 2>/dev/null; fi
fi
