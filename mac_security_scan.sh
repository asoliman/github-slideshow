#!/bin/bash
# In-depth macOS security & vulnerability scan (read-only, defensive).
# Usage:  chmod +x mac_security_scan.sh && ./mac_security_scan.sh
# For fuller coverage run once as an admin:  sudo ./mac_security_scan.sh
# Makes no changes to the system. Report: ~/Desktop/mac_security_report_<date>.txt
# Compatible with the stock macOS bash 3.2.

[ "$(uname)" = "Darwin" ] || { echo "macOS only."; exit 1; }

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -d "$REAL_HOME" ] || REAL_HOME="$HOME"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1

STAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$REAL_HOME/Desktop/mac_security_report_$STAMP.txt"
FINDINGS=$(mktemp -t secscan)
trap 'rm -f "$FINDINGS"' EXIT

# add SEVERITY "title" "detail" "recommended action"   (SEVERITY: 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW)
add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$FINDINGS"; }
info() { printf '  [*] %s\n' "$1"; }
step() { printf '\n== %s ==\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
# tmo SECONDS cmd args...  -> run with a time limit (macOS has no `timeout`)
tmo() { local t=$1; shift; perl -e 'alarm shift; exec @ARGV' "$t" "$@" 2>/dev/null; }

echo "macOS Security Scan - $(date)"
echo "User: $REAL_USER   Root: $([ $IS_ROOT = 1 ] && echo yes || echo 'no (some checks limited)')"

# ---------------------------------------------------------------- 1. OS / patching
step "1/16 OS version & patch level"
OSV=$(sw_vers -productVersion); BLD=$(sw_vers -buildVersion)
info "macOS $OSV ($BLD)  $(uname -m)"
UPD=$(tmo 90 softwareupdate --list 2>&1)
if echo "$UPD" | grep -qi "Label:\|\* "; then
  N=$(echo "$UPD" | grep -c "Label:")
  SEC=$(echo "$UPD" | grep -ci "security\|Rapid Security\|Background Security")
  if [ "$SEC" -gt 0 ]; then
    add 1 "Security updates pending" "$N update(s) available, including security content." "System Settings > General > Software Update > install all updates now."
  else
    add 3 "macOS updates pending" "$N update(s) available." "Install via System Settings > General > Software Update."
  fi
else
  info "No pending updates reported"
fi
AU=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null)
echo "$AU" | grep -q "AutomaticCheckEnabled = 0" && add 2 "Automatic update checks disabled" "macOS will not check for updates on its own." "Enable in Software Update > (i) Automatic updates."
echo "$AU" | grep -q "CriticalUpdateInstall = 0" && add 2 "Security responses/system files auto-install disabled" "Critical XProtect/security data updates are off." "Enable 'Install Security Responses and system files' in Automatic updates."
echo "$AU" | grep -q "ConfigDataInstall = 0" && add 2 "Config data auto-install disabled" "Malware definition updates are off." "Enable 'Install Security Responses and system files'."
MAJOR=${OSV%%.*}
[ "$MAJOR" -lt 13 ] 2>/dev/null && add 1 "macOS version is out of support" "macOS $OSV no longer receives security patches." "Upgrade to the newest macOS this Mac supports."

# ---------------------------------------------------------------- 2. Core protections
step "2/16 Core platform protections"
SIP=$(csrutil status 2>&1)
echo "$SIP" | grep -q "enabled" || add 1 "System Integrity Protection (SIP) is DISABLED" "$SIP" "Boot to Recovery, run: csrutil enable"
echo "$SIP" | grep -qi "custom\|unknown\|Configuration" && echo "$SIP" | grep -q "enabled" && echo "$SIP" | grep -qi "disabled" && add 2 "SIP partially disabled" "$SIP" "Boot to Recovery, run: csrutil enable"
AR=$(csrutil authenticated-root status 2>&1)
echo "$AR" | grep -qi "disabled" && add 1 "Authenticated Root Volume is disabled" "$AR" "Boot to Recovery: csrutil authenticated-root enable"
GK=$(spctl --status 2>&1)
echo "$GK" | grep -q "enabled" || add 1 "Gatekeeper is DISABLED" "$GK" "Run: sudo spctl --master-enable"
FV=$(fdesetup status 2>&1)
echo "$FV" | grep -q "On" || add 1 "FileVault disk encryption is OFF" "$FV - lost/stolen Mac exposes all data." "System Settings > Privacy & Security > FileVault > Turn On (store recovery key safely)."
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)
echo "$FW" | grep -qi "enabled\|State = [12]" || add 2 "Application firewall is OFF" "$FW" "System Settings > Network > Firewall > On."
ST=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1)
echo "$ST" | grep -qi "is on\|enabled" || add 4 "Firewall stealth mode off" "$ST" "Firewall Options > Enable stealth mode."
BI=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>&1)
echo "$BI" | grep -qi "ENABLED" && add 4 "Firewall auto-allows signed apps" "Signed apps may accept incoming connections without prompting." "Firewall Options > uncheck 'Automatically allow built-in/downloaded signed software' if you want stricter control."
XPB=/Library/Apple/System/Library/CoreServices/XProtect.bundle
[ -d "$XPB" ] || XPB=/System/Library/CoreServices/XProtect.bundle
XP=$(defaults read "$XPB/Contents/Info" CFBundleShortVersionString 2>/dev/null)
XPD=$(stat -f %Sm -t %Y-%m-%d "$XPB" 2>/dev/null)
info "XProtect version ${XP:-unknown} (updated ${XPD:-unknown})"
[ -z "$XP" ] && add 3 "Could not confirm XProtect version" "XProtect bundle not found." "Ensure automatic security updates are on and check updates."
if [ -n "$XPD" ]; then
  AGE=$(( ( $(date +%s) - $(date -j -f %Y-%m-%d "$XPD" +%s 2>/dev/null || echo 0) ) / 86400 ))
  [ "$AGE" -gt 60 ] 2>/dev/null && add 2 "XProtect malware definitions are $AGE days old" "Last updated $XPD." "Enable 'Install Security Responses and system files' and update macOS."
fi
if [ -f /var/db/ConfigurationProfiles/Settings/.profilesAreInstalled ] || profiles list 2>/dev/null | grep -qi "profileIdentifier"; then
  PROF=$(profiles list 2>/dev/null | grep -i "profileIdentifier" | head -5)
  add 3 "Configuration profile(s)/MDM installed" "$PROF" "Verify you recognize these (System Settings > Privacy & Security > Profiles). Remove unknown ones."
fi
NV=$(nvram -p 2>/dev/null | grep -c "fmm-mobileme-token-FMM")
[ "$NV" = "0" ] && add 4 "Find My Mac appears off" "No Find My token in NVRAM." "Enable Find My > Find My Mac in Apple ID settings."

# ---------------------------------------------------------------- 3. Accounts
step "3/16 User accounts & authentication"
ADMINS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2)
info "Admin users:$ADMINS"
NADM=$(echo "$ADMINS" | wc -w | tr -d ' ')
[ "$NADM" -gt 2 ] && add 3 "Many admin accounts ($NADM)" "Admins:$ADMINS" "Daily-use accounts should be Standard users; keep one admin."
ROOTAA=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null)
[ -n "$ROOTAA" ] && add 2 "Root account is enabled" "$ROOTAA" "Disable: dsenableroot -d  (Directory Utility)."
GUEST=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
[ "$GUEST" = "1" ] && add 2 "Guest account enabled" "Anyone can log in as guest." "Users & Groups > Guest User > off."
AUTOL=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
[ -n "$AUTOL" ] && add 1 "Automatic login enabled for '$AUTOL'" "Mac boots straight into that account with no password." "System Settings > Users & Groups > Automatic login: Off."
HINT=$(defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint 2>/dev/null)
[ -n "$HINT" ] && [ "$HINT" != "0" ] && add 4 "Password hints shown at login" "RetriesUntilHint=$HINT" "Lock Screen settings > Show password hints: off."
SHOWFULL=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null)
[ "$SHOWFULL" != "1" ] && add 4 "Login window lists user accounts" "Usernames visible to anyone at the login screen." "Lock Screen > Login window shows: Name and password."
for U in $(dscl . list /Users UniqueID | awk '$2>=500 {print $1}'); do
  if [ $IS_ROOT = 1 ]; then
    TK=$(sysadminctl -secureTokenStatus "$U" 2>&1)
    echo "$TK" | grep -qi "DISABLED" && add 2 "No Secure Token for user '$U'" "$TK" "Grant from an admin: sysadminctl -secureTokenOn $U -password - -adminUser <admin> -adminPassword -  (also needed for FileVault login on Apple Silicon)."
  fi
  PWPOL=$(pwpolicy -u "$U" -getaccountpolicies 2>/dev/null | grep -c policyAttributePassword)
  info "user $U: password policy rules=$PWPOL"
done
SDF=$(grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v "^#")
[ -n "$SDF" ] && add 2 "sudo NOPASSWD rules present" "$SDF" "Remove NOPASSWD entries with visudo unless strictly required."
SSD=$(grep -rE "timestamp_timeout" /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v "^#")
[ -n "$SSD" ] && info "sudo timeout customised: $SSD"
SP=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
SPD=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
if [ "$SP" = "0" ]; then add 2 "No password required after screensaver/sleep" "askForPassword=0" "Lock Screen > Require password after screen saver/display off: Immediately."
elif [ -n "$SPD" ] && [ "$SPD" -gt 60 ] 2>/dev/null; then add 3 "Long delay before password required ($SPD s)" "askForPasswordDelay=$SPD" "Set to Immediately or <= 5 seconds."; fi

# ---------------------------------------------------------------- 4. Sharing & remote access
step "4/16 Sharing & remote access services"
port_open() { nc -z -w 1 127.0.0.1 "$1" >/dev/null 2>&1; }
port_open 22   && add 2 "Remote Login (SSH) is enabled" "Port 22 accepting connections." "System Settings > General > Sharing > Remote Login: off (or restrict users, use keys only)."
port_open 5900 && add 1 "Screen Sharing / Remote Management (VNC) is enabled" "Port 5900 open." "Sharing > Screen Sharing / Remote Management: off unless needed."
port_open 445  && add 2 "File Sharing (SMB) is enabled" "Port 445 open." "Sharing > File Sharing: off if unused."
port_open 548  && add 3 "AFP File Sharing enabled" "Port 548 open." "Disable File Sharing (AFP)."
port_open 3283 && add 2 "Apple Remote Desktop agent running" "Port 3283 open." "Disable Remote Management."
port_open 631  && add 4 "Printer sharing (CUPS) exposed" "Port 631 open." "Disable Printer Sharing if unused."
port_open 3689 && add 4 "Media sharing (iTunes/Music) enabled" "Port 3689 open." "Disable Media Sharing."
RAE=$(launchctl print-disabled system 2>/dev/null | grep -i "eppc" | grep -i "enabled")
[ -n "$RAE" ] && add 2 "Remote Apple Events enabled" "$RAE" "Sharing > Advanced > Remote Apple Events: off."
if have sharing; then
  SH=$(sharing -l 2>/dev/null | grep -E "name:|path:" | head -10)
  [ -n "$SH" ] && add 3 "Shared folders defined" "$SH" "Review in Sharing > File Sharing; remove unneeded shares."
fi
BTS=$(defaults read /Library/Preferences/com.apple.Bluetooth 2>/dev/null | grep -i "DiscoverableState" | head -1)
info "Bluetooth: ${BTS:-n/a}"

# ---------------------------------------------------------------- 5. Network exposure
step "5/16 Listening network services"
LISTEN=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u)
echo "$LISTEN" | sed 's/^/    /'
EXPOSED=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 && ($9 ~ /^\*:/ || $9 ~ /^\[::\]:/) {print $1" "$9}' | sort -u)
if [ -n "$EXPOSED" ]; then
  add 3 "Services listening on ALL interfaces" "$(echo "$EXPOSED" | head -15)" "Confirm each is intended; bind dev servers to 127.0.0.1; block others in the firewall."
fi
UDPX=$(lsof -nP -iUDP 2>/dev/null | awk 'NR>1 && $9 ~ /^\*:/ {print $1" "$9}' | sort -u | head -15)
[ -n "$UDPX" ] && info "UDP wildcard listeners: $(echo "$UDPX" | tr '\n' ';')"
WIFI_DEV=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1)
if [ -n "$WIFI_DEV" ]; then
  CUR=$(tmo 25 system_profiler SPAirPortDataType | awk '/Current Network Information:/{f=1} f' | head -12)
  echo "$CUR" | grep -qi "Security: None\|Open" && add 2 "Connected to an OPEN (unencrypted) Wi-Fi" "$(echo "$CUR" | head -3)" "Disconnect; use WPA2/WPA3 networks or a VPN."
  echo "$CUR" | grep -qi "WEP\|WPA Personal$" && add 3 "Weak Wi-Fi security protocol in use" "$(echo "$CUR" | grep -i security)" "Use WPA2/WPA3 on the router."
  OPENPREF=$(networksetup -listpreferredwirelessnetworks "$WIFI_DEV" 2>/dev/null | wc -l | tr -d ' ')
  [ "$OPENPREF" -gt 25 ] && add 4 "Large saved Wi-Fi list ($OPENPREF)" "Mac may auto-join old/rogue networks." "Prune saved networks in Wi-Fi > Advanced."
fi
PROXY=$(scutil --proxy 2>/dev/null | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable" | grep "1")
[ -n "$PROXY" ] && add 2 "System proxy / PAC configured" "$(scutil --proxy | grep -E 'Proxy|Port' | head -8)" "Verify the proxy is yours. Unexpected proxies enable traffic interception."
DNS=$(scutil --dns 2>/dev/null | awk '/nameserver\[/ {print $3}' | sort -u | tr '\n' ' ')
info "DNS servers: $DNS"
HOSTS=$(grep -vE '^\s*#|^\s*$|localhost|broadcasthost|^::1' /etc/hosts 2>/dev/null)
[ -n "$HOSTS" ] && add 2 "Custom entries in /etc/hosts" "$(echo "$HOSTS" | head -10)" "Remove entries you didn't add (can redirect banking/update domains)."
VPNS=$(scutil --nc list 2>/dev/null | grep -c "Connected")
info "Active VPN connections: $VPNS"

# ---------------------------------------------------------------- 6. Persistence
step "6/16 Persistence: LaunchAgents/Daemons, login items, cron"
LOCS="/Library/LaunchAgents /Library/LaunchDaemons $REAL_HOME/Library/LaunchAgents"
SUSP=""
for D in $LOCS; do
  [ -d "$D" ] || continue
  for P in "$D"/*.plist; do
    [ -f "$P" ] || continue
    PROG=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$P" 2>/dev/null)
    [ -z "$PROG" ] && PROG=$(/usr/libexec/PlistBuddy -c "Print :Program" "$P" 2>/dev/null)
    LBL=$(basename "$P")
    case "$PROG" in
      /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/Users/Shared/*|"$REAL_HOME"/.*|"$REAL_HOME"/Library/Caches/*|"$REAL_HOME"/Downloads/*)
        add 1 "Launch item runs from a suspicious location" "$P -> $PROG" "Investigate immediately; if unrecognised unload and delete: launchctl bootout, then rm the plist and binary." ;;
      /bin/sh|/bin/bash|/bin/zsh|/usr/bin/python*|/usr/bin/osascript|/usr/bin/curl|/bin/sh)
        add 2 "Launch item runs a shell/script interpreter" "$P -> $PROG $(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$P" 2>/dev/null | tr -s '\n ' ' ' | cut -c1-200)" "Verify it is legitimate; scripts launched at login are a common malware pattern." ;;
    esac
    if [ -n "$PROG" ] && [ -f "$PROG" ]; then
      if ! codesign -v "$PROG" >/dev/null 2>&1; then
        case "$LBL" in com.apple.*) ;; *) SUSP="$SUSP\n$LBL ($PROG)";; esac
      fi
    elif [ -n "$PROG" ]; then
      case "$LBL" in com.apple.*) ;; *) info "Orphan launch item (binary missing): $LBL -> $PROG";; esac
    fi
  done
done
[ -n "$SUSP" ] && add 2 "Launch items with unsigned/invalid binaries" "$(printf "$SUSP" | head -12)" "Confirm the software is trusted; remove or reinstall from the vendor."
THIRD=$(ls /Library/LaunchAgents /Library/LaunchDaemons "$REAL_HOME/Library/LaunchAgents" 2>/dev/null | grep -v "^com.apple\|^$\|:$" | sort -u | head -40)
info "Third-party launch items: $(echo "$THIRD" | tr '\n' ' ')"
LI=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
info "Login items: ${LI:-none}"
CRON=$(crontab -l 2>/dev/null | grep -v '^#')
[ -n "$CRON" ] && add 3 "User crontab entries present" "$CRON" "Verify each job; cron persistence is a malware favourite."
[ -s /etc/crontab ] && grep -vE '^\s*#|^\s*$|^SHELL|^PATH' /etc/crontab >/dev/null 2>&1 && info "/etc/crontab has content"
ATJ=$(atq 2>/dev/null)
[ -n "$ATJ" ] && add 3 "'at' jobs scheduled" "$ATJ" "Review with atq / atrm."
for RC in .zshrc .zprofile .zshenv .bash_profile .bashrc .profile; do
  F="$REAL_HOME/$RC"; [ -f "$F" ] || continue
  BAD=$(grep -nE "curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|base64 (-d|--decode)|eval \"?\$\(curl|nc -e|/dev/tcp/|osascript -e" "$F" | head -5)
  [ -n "$BAD" ] && add 1 "Suspicious command in ~/$RC" "$BAD" "Inspect the line; remove if not yours (possible persistence/backdoor)."
done
SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -E "activated enabled" | grep -v "com.apple")
[ -n "$SYSEXT" ] && info "Third-party system extensions: $(echo "$SYSEXT" | wc -l | tr -d ' ')"
KEXT=$(tmo 20 kmutil showloaded --list-only 2>/dev/null | grep -v "com.apple" | head -10)
[ -n "$KEXT" ] && add 3 "Third-party kernel extensions loaded" "$KEXT" "Remove unneeded kexts; prefer system-extension based software."

# ---------------------------------------------------------------- 7. Processes
step "7/16 Running processes"
BADP=$(ps -axo pid,user,comm | awk 'NR>1' | grep -E "/(tmp|private/tmp|var/tmp|private/var/tmp)/|/Users/Shared/|/\.[A-Za-z0-9_-]+/" | grep -v "grep" | head -10)
[ -n "$BADP" ] && add 1 "Processes running from temp/hidden/shared locations" "$BADP" "Identify with: lsof -p <pid>; kill and remove if unknown."
MINER=$(ps -axo pid,pcpu,comm | awk 'NR>1 && $2>85 {print}' | head -5)
[ -n "$MINER" ] && add 3 "Process using >85% CPU" "$MINER" "Check Activity Monitor for unknown processes (cryptominers are common)."
KNOWNBAD="xmrig|kinsing|cpuminer|minerd|OSX.Dok|MacKeeper|Genieo|MacDownloader|Shlayer|AdLoad|WizardUpdate|CoinMiner|Bundlore"
KB=$(ps -axo comm | grep -Ei "$KNOWNBAD")
[ -n "$KB" ] && add 1 "Known malware/adware process name running" "$KB" "Remove the app, its launch items and run a scan with Malwarebytes."

# ---------------------------------------------------------------- 8. Installed apps
step "8/16 Installed applications (signature check, can take a few minutes)"
KNOWNPUP="MacKeeper|Advanced Mac Cleaner|Mac Auto Fixer|Genieo|Spigot|MacCleaner|Mac Adware Cleaner|Shlayer|Bundlore|Mackeeper|Cleaner One|OneStart|Search Baron|Conduit"
PUP=$(ls /Applications "$REAL_HOME/Applications" 2>/dev/null | grep -Ei "$KNOWNPUP")
[ -n "$PUP" ] && add 2 "Potentially unwanted / adware applications" "$PUP" "Uninstall these (and their LaunchAgents/extensions)."
UNS=""; CNT=0
for A in /Applications/*.app "$REAL_HOME"/Applications/*.app; do
  [ -d "$A" ] || continue
  CNT=$((CNT+1))
  if ! codesign --verify --deep "$A" >/dev/null 2>&1; then UNS="$UNS\n$(basename "$A")"; continue; fi
  spctl -a -t exec "$A" >/dev/null 2>&1 || UNS="$UNS\n$(basename "$A") (rejected by Gatekeeper)"
done
info "Scanned $CNT apps"
[ -n "$UNS" ] && add 3 "Apps with invalid signature / failing Gatekeeper" "$(printf "$UNS" | head -15)" "Re-download from the developer or uninstall."
QUAR=$(find "$REAL_HOME/Downloads" -maxdepth 2 \( -name "*.pkg" -o -name "*.dmg" -o -name "*.command" -o -name "*.app" \) 2>/dev/null | head -10)
[ -n "$QUAR" ] && add 4 "Old installers in Downloads" "$QUAR" "Delete installers you no longer need."
if have brew; then
  OUT=$(tmo 60 brew outdated | head -20)
  [ -n "$OUT" ] && add 3 "Outdated Homebrew packages" "$(echo "$OUT" | tr '\n' ' ')" "Run: brew update && brew upgrade"
fi
have pip3 && PIPO=$(tmo 30 pip3 list --outdated | wc -l | tr -d ' ') && [ "${PIPO:-0}" -gt 10 ] && add 4 "Many outdated Python packages ($PIPO)" "pip3 list --outdated" "Upgrade packages inside virtualenvs."
have npm && NPMO=$(tmo 30 npm -g outdated | wc -l | tr -d ' ') && [ "${NPMO:-0}" -gt 3 ] && add 4 "Outdated global npm packages" "$NPMO packages" "npm update -g"
APPS=$(ls /Applications | tr '\n' ' ')
echo "$APPS" | grep -qi "Docker" && [ -S /var/run/docker.sock ] && [ "$(stat -f %Lp /var/run/docker.sock 2>/dev/null)" = "777" ] && add 3 "Docker socket world-writable" "/var/run/docker.sock" "Restrict permissions; Docker socket access is equivalent to root."

# ---------------------------------------------------------------- 9. Keys, secrets, files
step "9/16 SSH keys, credentials and file permissions"
SSHD="$REAL_HOME/.ssh"
if [ -d "$SSHD" ]; then
  SP=$(stat -f %Lp "$SSHD"); [ "$SP" != "700" ] && add 3 "~/.ssh permissions are $SP" "Should be 700." "chmod 700 ~/.ssh"
  for K in "$SSHD"/id_* ; do
    [ -f "$K" ] || continue; case "$K" in *.pub) continue;; esac
    KP=$(stat -f %Lp "$K"); [ "$KP" != "600" ] && [ "$KP" != "400" ] && add 2 "Private key $K permissions $KP" "Readable by others." "chmod 600 $K"
    if ssh-keygen -y -P "" -f "$K" >/dev/null 2>&1; then
      add 2 "SSH private key has NO passphrase: $(basename "$K")" "$K" "Add one: ssh-keygen -p -f $K"
    fi
    ssh-keygen -l -f "$K" 2>/dev/null | grep -qE "^(1024|512) |\(DSA\)|\(RSA\)" && ssh-keygen -l -f "$K" 2>/dev/null | grep -qE "^(1024|2048) " && add 4 "Weak/old SSH key type or size: $(basename "$K")" "$(ssh-keygen -l -f "$K" 2>/dev/null)" "Generate ed25519: ssh-keygen -t ed25519"
  done
  [ -f "$SSHD/authorized_keys" ] && add 3 "authorized_keys present (remote key logins allowed)" "$(wc -l < "$SSHD/authorized_keys" | tr -d ' ') key(s)" "Verify each key is yours; remove unknown ones."
fi
SSHC=/etc/ssh/sshd_config
[ -f $SSHC ] && grep -qiE "^\s*PasswordAuthentication\s+yes" $SSHC /etc/ssh/sshd_config.d/* 2>/dev/null && add 3 "SSH password authentication allowed" "sshd_config" "Set PasswordAuthentication no; use keys."
[ -f $SSHC ] && grep -qiE "^\s*PermitRootLogin\s+yes" $SSHC /etc/ssh/sshd_config.d/* 2>/dev/null && add 1 "SSH root login permitted" "sshd_config" "Set PermitRootLogin no."
SECF=$(find "$REAL_HOME" -maxdepth 4 -type f \( -name ".env" -o -name ".netrc" -o -name "credentials" -o -name "*.pem" -o -name "id_rsa" -o -name ".npmrc" -o -name ".pypirc" \) -not -path "*/node_modules/*" -not -path "*/Library/*" 2>/dev/null | head -15)
[ -n "$SECF" ] && add 3 "Credential/secret files found in home folder" "$SECF" "Ensure they're not world-readable, not in cloud-synced/public repos; rotate if exposed."
AWS="$REAL_HOME/.aws/credentials"
[ -f "$AWS" ] && add 3 "Plaintext AWS credentials file" "$AWS" "Use SSO/short-lived credentials; rotate keys regularly."
WW=$(find /usr/local/bin /usr/local/lib /opt/homebrew/bin -maxdepth 2 -perm -0002 -type f 2>/dev/null | head -10)
[ -n "$WW" ] && add 2 "World-writable files in PATH directories" "$WW" "chmod o-w on these files (binary hijack risk)."
HP=$(find "$REAL_HOME" -maxdepth 1 -perm -0007 2>/dev/null | head -5)
[ -n "$HP" ] && add 3 "Home folder content is world-accessible" "$HP" "chmod o-rwx"
HPH=$(stat -f %Lp "$REAL_HOME"); case "$HPH" in *[1-7]) add 3 "Home directory permissions $HPH" "Other users can browse your home folder." "chmod 750 ~ (or 700)";; esac
TMPX=$(echo "$PATH" | tr ':' '\n' | grep -E "^\.?$|^/tmp")
[ -n "$TMPX" ] && add 2 "Current directory or /tmp in PATH" "$PATH" "Remove from shell rc files."

# ---------------------------------------------------------------- 10. Certificates / trust
step "10/16 Certificates & trust"
TS=$(security dump-trust-settings -d 2>&1 | grep -c "Cert [0-9]")
[ "${TS:-0}" -gt 0 ] && add 2 "Admin-level custom trusted certificates ($TS)" "$(security dump-trust-settings -d 2>&1 | grep 'Cert [0-9]' | head -10)" "Open Keychain Access > System; remove unknown root CAs (enables HTTPS interception)."
UTS=$(security dump-trust-settings 2>&1 | grep -c "Cert [0-9]")
[ "${UTS:-0}" -gt 0 ] && add 3 "User-level custom trusted certificates ($UTS)" "$(security dump-trust-settings 2>&1 | grep 'Cert [0-9]' | head -10)" "Review in Keychain Access > login; remove unknown root CAs."
EXPC=$(security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null | wc -l | tr -d ' ')
info "System keychain PEM lines: $EXPC"
KCL=$(security show-keychain-info "$REAL_HOME/Library/Keychains/login.keychain-db" 2>&1)
echo "$KCL" | grep -q "no-timeout" && add 3 "Login keychain never auto-locks" "$KCL" "Keychain Access > Edit > Change Settings: lock after inactivity."

# ---------------------------------------------------------------- 11. Privacy / TCC
step "11/16 Privacy permissions (TCC)"
TCCDB="$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -r "$TCCDB" ] && have sqlite3; then
  FDA=$(sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "select client from access where service='kTCCServiceSystemPolicyAllFiles' and auth_value=2;" 2>/dev/null)
  ACC=$(sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "select client from access where service='kTCCServiceAccessibility' and auth_value=2;" 2>/dev/null)
  SCR=$(sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "select client from access where service='kTCCServiceScreenCapture' and auth_value=2;" 2>/dev/null)
  [ -n "$FDA" ] && info "Full Disk Access: $(echo "$FDA" | tr '\n' ' ')"
  [ -n "$ACC" ] && info "Accessibility: $(echo "$ACC" | tr '\n' ' ')"
  [ -n "$SCR" ] && info "Screen Recording: $(echo "$SCR" | tr '\n' ' ')"
  [ -n "$FDA$ACC$SCR" ] && add 4 "Apps hold powerful privacy permissions" "FDA: $(echo $FDA) | Accessibility: $(echo $ACC) | Screen: $(echo $SCR)" "System Settings > Privacy & Security: remove any app you don't recognise."
else
  info "TCC database not readable (grant Terminal Full Disk Access to enable this check)"
fi

# ---------------------------------------------------------------- 12. Browsers
step "12/16 Browser exposure"
CH="$REAL_HOME/Library/Application Support/Google/Chrome/Default/Extensions"
[ -d "$CH" ] && info "Chrome extensions installed: $(ls "$CH" | wc -l | tr -d ' ')"
[ -d "$CH" ] && [ "$(ls "$CH" | wc -l)" -gt 12 ] && add 4 "Many Chrome extensions ($(ls "$CH" | wc -l | tr -d ' '))" "Extensions can read all page data." "Remove unused extensions at chrome://extensions."
SAFEXT=$(tmo 15 pluginkit -mAvvv -p com.apple.Safari.extension 2>/dev/null | grep -c "Path")
info "Safari extensions: $SAFEXT"
for B in "Google Chrome" "Firefox" "Microsoft Edge" "Brave Browser"; do
  [ -d "/Applications/$B.app" ] && V=$(defaults read "/Applications/$B.app/Contents/Info" CFBundleShortVersionString 2>/dev/null) && info "$B $V (verify it's the latest)"
done

# ---------------------------------------------------------------- 13. Backups & recovery
step "13/16 Backups & data protection"
TM=$(tmutil destinationinfo 2>&1)
if echo "$TM" | grep -qi "No destinations"; then add 3 "No Time Machine backup configured" "$TM" "Set up Time Machine to an external encrypted drive."
else
  LASTB=$(tmutil latestbackup 2>/dev/null); info "Latest TM backup: ${LASTB:-none}"
  [ -z "$LASTB" ] && add 3 "Time Machine configured but no completed backup found" "$TM" "Connect the drive and run a backup."
fi
ICL=$(defaults read MobileMeAccounts Accounts 2>/dev/null | grep -c AccountID)
info "iCloud accounts signed in: $ICL"

# ---------------------------------------------------------------- 14. Logs
step "14/16 Log analysis (last 2 days)"
FAILAUTH=$(tmo 45 log show --last 2d --style compact --predicate 'eventMessage CONTAINS "Failed to authenticate" OR eventMessage CONTAINS "authentication failure"' 2>/dev/null | wc -l | tr -d ' ')
info "Failed authentication events: $FAILAUTH"
[ "${FAILAUTH:-0}" -gt 30 ] && add 3 "Many failed authentication events ($FAILAUTH)" "Possible brute force or stuck process." "Check source with: log show --last 2d --predicate 'eventMessage CONTAINS \"authentication\"'"
SSHF=$(tmo 45 log show --last 2d --style compact --predicate 'process == "sshd" AND eventMessage CONTAINS "Failed"' 2>/dev/null | wc -l | tr -d ' ')
[ "${SSHF:-0}" -gt 5 ] && add 2 "Failed SSH login attempts ($SSHF)" "Someone is probing SSH." "Disable Remote Login or restrict by key and firewall."
SUDOF=$(tmo 45 log show --last 2d --style compact --predicate 'process == "sudo" AND eventMessage CONTAINS "incorrect password"' 2>/dev/null | wc -l | tr -d ' ')
[ "${SUDOF:-0}" -gt 5 ] && add 3 "Failed sudo attempts ($SUDOF)" "Repeated wrong sudo passwords." "Verify these were you."
GKB=$(tmo 45 log show --last 2d --style compact --predicate 'process == "syspolicyd" AND eventMessage CONTAINS "blocked"' 2>/dev/null | wc -l | tr -d ' ')
info "Gatekeeper blocks: $GKB"
LWE=$(tmo 45 log show --last 2d --style compact --predicate 'process == "loginwindow" AND messageType == error' 2>/dev/null | wc -l | tr -d ' ')
info "loginwindow errors (2d): $LWE"
[ "${LWE:-0}" -gt 50 ] && add 4 "Many loginwindow errors ($LWE)" "May relate to the login hang." "Run: log show --last 2d --predicate 'process==\"loginwindow\"' | tail -100"
PAN=$(ls /Library/Logs/DiagnosticReports/*.panic 2>/dev/null | wc -l | tr -d ' ')
[ "${PAN:-0}" -gt 0 ] && add 3 "Kernel panic reports exist ($PAN)" "/Library/Logs/DiagnosticReports" "Review for third-party drivers; update/remove offending software."

# ---------------------------------------------------------------- 15. Hardening & firmware
step "15/16 Firmware, hardening & misc"
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
  SECBOOT=$(tmo 20 system_profiler SPiBridgeDataType | grep -i "Secure Boot\|Boot Policy" | head -3)
  [ -n "$SECBOOT" ] && info "$SECBOOT"
  [ "$IS_ROOT" = 1 ] && have bputil && BP=$(bputil -d 2>&1 | grep -i "security mode\|Permissive" | head -2) && echo "$BP" | grep -qi "permissive\|reduced" && add 1 "Boot security is Reduced/Permissive" "$BP" "Recovery > Startup Security Utility > Full Security."
else
  FW=$(firmwarepasswd -check 2>&1); echo "$FW" | grep -qi "No" && add 3 "No firmware password set (Intel)" "$FW" "Set a firmware password in Recovery."
fi
USBR=$(defaults read /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation 2>/dev/null)
[ "$USBR" = "1" ] && add 1 "Library validation disabled" "Allows unsigned code injection into apps." "defaults delete /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation"
AMFI=$(nvram boot-args 2>/dev/null)
echo "$AMFI" | grep -qE "amfi_get_out_of_my_way|cs_enforcement_disable|-arm64e_preview_abi" && add 1 "Code-signing enforcement weakened (boot-args)" "$AMFI" "Remove: sudo nvram -d boot-args"
SUDOV=$(sudo -V 2>/dev/null | head -1 | awk '{print $NF}'); info "sudo version: ${SUDOV:-n/a}"
OPENV=$(openssl version 2>/dev/null); info "$OPENV"
echo "$OPENV" | grep -qi "LibreSSL 2\.\|OpenSSL 1\.0\|OpenSSL 1\.1" && add 4 "Old OpenSSL/LibreSSL" "$OPENV" "Update via Homebrew if you depend on it."
SIRI=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null)
AIRD=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null)
[ "$AIRD" = "Everyone" ] && add 4 "AirDrop is set to Everyone" "$AIRD" "AirDrop > Contacts Only."
CAMLOG=$(tmo 45 log show --last 1d --style compact --predicate 'subsystem == "com.apple.UVCExtension" OR eventMessage CONTAINS "camera"' 2>/dev/null | wc -l | tr -d ' ')
info "Camera-related log lines (24h): $CAMLOG"
SIZE=$(df -k / | awk 'NR==2 {print int($4/1024/1024)}')
[ "${SIZE:-100}" -lt 10 ] && add 4 "Low free disk space (${SIZE}GB)" "Low space prevents updates and can break login." "Free up space (>20GB recommended)."

# ---------------------------------------------------------------- 16. Report
step "16/16 Building report"
{
echo "=============================================================="
echo "        macOS SECURITY & VULNERABILITY REPORT"
echo "=============================================================="
echo "Date:    $(date)"
echo "Host:    $(scutil --get ComputerName 2>/dev/null)  ($(hostname))"
echo "System:  macOS $OSV ($BLD) $ARCH"
echo "User:    $REAL_USER     Scan mode: $([ $IS_ROOT = 1 ] && echo 'root/full' || echo 'user (limited)')"
C1=$(grep -c "^1	" "$FINDINGS"); C2=$(grep -c "^2	" "$FINDINGS")
C3=$(grep -c "^3	" "$FINDINGS"); C4=$(grep -c "^4	" "$FINDINGS")
SCORE=$((100 - C1*25 - C2*10 - C3*4 - C4*1)); [ $SCORE -lt 0 ] && SCORE=0
echo
echo "SUMMARY"
echo "  CRITICAL : $C1"
echo "  HIGH     : $C2"
echo "  MEDIUM   : $C3"
echo "  LOW      : $C4"
echo "  Security score: $SCORE / 100"
for SEV in 1 2 3 4; do
  case $SEV in 1) NAME="CRITICAL - fix immediately";; 2) NAME="HIGH - fix soon";; 3) NAME="MEDIUM - plan to fix";; 4) NAME="LOW - hardening / housekeeping";; esac
  echo
  echo "--------------------------------------------------------------"
  echo " $NAME"
  echo "--------------------------------------------------------------"
  I=0
  while IFS="$(printf '\t')" read -r S T D A; do
    [ "$S" = "$SEV" ] || continue
    I=$((I+1))
    echo
    echo "[$I] $T"
    echo "    Details: $(printf '%s' "$D" | sed 's/\\n/ | /g' | tr '\n' ' ' | cut -c1-600)"
    echo "    Action : $A"
  done < "$FINDINGS"
  [ "$(grep -c "^$SEV	" "$FINDINGS")" = "0" ] && echo "  None found."
done
echo
echo "--------------------------------------------------------------"
echo " TOP RECOMMENDED ACTIONS (in order)"
echo "--------------------------------------------------------------"
N=0
for SEV in 1 2 3; do
  while IFS="$(printf '\t')" read -r S T D A; do
    [ "$S" = "$SEV" ] || continue
    N=$((N+1)); [ $N -gt 10 ] && break
    echo "  $N. $T -> $A"
  done < "$FINDINGS"
done
[ $N -eq 0 ] && echo "  No critical/high/medium issues found. Keep macOS and apps up to date."
echo
echo "NOTES"
echo "  - This scan is read-only and heuristic: findings are leads to verify, not proof of compromise."
echo "  - It cannot replace a dedicated anti-malware scanner. Consider a second opinion with Malwarebytes (free scan)."
echo "  - Re-run with sudo for Secure Token, boot security and TCC checks."
echo "  - Report saved to: $REPORT"
} | tee "$REPORT"
echo
echo "Done. Report: $REPORT"
