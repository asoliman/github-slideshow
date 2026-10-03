#!/bin/bash
# Mac health check (hardware + software + login-hang diagnostics).
# Usage:  chmod +x mac_health_check.sh && ./mac_health_check.sh
# Report is saved to ~/Desktop/mac_health_<date>.txt

[ "$(uname)" = "Darwin" ] || { echo "This script is for macOS only."; exit 1; }

REPORT="$HOME/Desktop/mac_health_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

section() { printf '\n==================== %s ====================\n' "$1"; }
run() { echo "\$ $*"; "$@" 2>&1; echo; }
sh_() { echo "\$ $1"; bash -c "$1" 2>&1; echo; }

echo "Mac health check - $(date)"
echo "Tip: run with 'sudo ./mac_health_check.sh' for extra detail (secure tokens, full logs)."

section "1. SYSTEM OVERVIEW"
run sw_vers
sh_ "uname -a"
sh_ "system_profiler SPHardwareDataType | sed -n '1,30p'"
sh_ "uptime"
sh_ "sysctl -n machdep.cpu.brand_string"

section "2. macOS UPDATES"
sh_ "softwareupdate --list 2>&1 | head -30"

section "3. STORAGE"
sh_ "df -h / /System/Volumes/Data 2>/dev/null"
sh_ "diskutil list internal"
sh_ "diskutil info / | grep -Ei 'SMART|Volume Name|File System|Free|Capacity|Solid State'"
sh_ "diskutil verifyVolume / 2>&1 | tail -15"
sh_ "diskutil apfs list | grep -Ei 'FileVault|Name:|Capacity (In Use|Not Allocated)|Encrypted'"
sh_ "du -sh ~/Library/Caches ~/Downloads ~/.Trash 2>/dev/null"
sh_ "tmutil listlocalsnapshots / 2>/dev/null | head -10"

section "4. MEMORY"
sh_ "memory_pressure | tail -8"
sh_ "vm_stat | head -12"
sh_ "sysctl vm.swapusage"
sh_ "top -l 1 -o mem -n 8 -stats pid,command,mem,cpu | tail -12"

section "5. CPU / LOAD / TOP PROCESSES"
sh_ "top -l 1 | head -12"
sh_ "ps -Ao pid,pcpu,pmem,comm -r | head -10"

section "6. BATTERY"
sh_ "system_profiler SPPowerDataType | grep -Ei 'Cycle Count|Condition|Maximum Capacity|Charge|Connected|Wattage|Full Charge'"
sh_ "pmset -g batt"
sh_ "pmset -g assertions | head -15"

section "7. THERMAL / POWER"
sh_ "pmset -g thermlog 2>&1 | head -10"
sh_ "pmset -g | head -25"

section "8. DISPLAY / GRAPHICS / USB / THUNDERBOLT"
sh_ "system_profiler SPDisplaysDataType | head -20"
sh_ "system_profiler SPUSBDataType | head -25"

section "9. NETWORK"
sh_ "networksetup -listallhardwareports | grep -E 'Hardware Port|Device'"
sh_ "ifconfig en0 | grep -E 'inet |status'"
sh_ "scutil --dns | grep nameserver | sort -u"
sh_ "ping -c 3 -t 5 1.1.1.1"
sh_ "ping -c 3 -t 5 apple.com"
sh_ "networksetup -getairportnetwork en0"

section "10. SECURITY"
sh_ "csrutil status"
sh_ "fdesetup status"
sh_ "spctl --status"
sh_ "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
sh_ "system_profiler SPiBridgeDataType 2>/dev/null | head -10"

section "11. USER ACCOUNTS (login-hang relevant)"
sh_ "dscl . list /Users UniqueID | awk '\$2>=500'"
sh_ "who"
sh_ "last -10"
for u in $(dscl . list /Users UniqueID | awk '$2>=500 {print $1}'); do
  echo "--- $u ---"
  sh_ "sysadminctl -secureTokenStatus $u 2>&1"
  sh_ "dscl . read /Users/$u AuthenticationAuthority 2>/dev/null | head -3"
  sh_ "dscl . read /Users/$u NFSHomeDirectory"
  sh_ "du -sh /Users/$u 2>/dev/null"
  sh_ "ls /Users/$u/Library/LaunchAgents 2>/dev/null"
done
sh_ "defaults read /Library/Preferences/.GlobalPreferences MultipleSessionEnabled 2>&1"
sh_ "defaults read /Library/Preferences/com.apple.loginwindow 2>&1 | head -25"

section "12. LOGIN ITEMS / LAUNCH DAEMONS / EXTENSIONS"
sh_ "ls /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null"
sh_ "ls ~/Library/LaunchAgents 2>/dev/null"
sh_ "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>&1"
sh_ "systemextensionsctl list 2>&1 | head -20"
sh_ "kextstat 2>/dev/null | grep -v com.apple | head -10"
sh_ "profiles list 2>&1 | head -10"

section "13. LOGINWINDOW / AUTH LOGS (last 24h)"
sh_ "log show --last 24h --style compact --predicate 'process == \"loginwindow\" AND (messageType == error OR messageType == fault)' 2>/dev/null | tail -40"
sh_ "log show --last 24h --style compact --predicate 'process == \"opendirectoryd\" AND messageType == error' 2>/dev/null | tail -20"
sh_ "log show --last 24h --style compact --predicate 'subsystem == \"com.apple.securityd\" AND messageType == error' 2>/dev/null | tail -20"

section "14. CRASHES / PANICS / SHUTDOWN CAUSES"
sh_ "ls -lt /Library/Logs/DiagnosticReports 2>/dev/null | head -10"
sh_ "ls -lt ~/Library/Logs/DiagnosticReports 2>/dev/null | head -10"
sh_ "ls -lt /Library/Logs/DiagnosticReports/*.panic /Library/Logs/DiagnosticReports/Retired/*.panic 2>/dev/null | head -5"
sh_ "log show --last 7d --style compact --predicate 'eventMessage contains \"Previous shutdown cause\"' 2>/dev/null | tail -5"

section "15. HARDWARE DIAGNOSTICS NOTE"
echo "Apple Silicon: shut down, press and hold the power button until startup options appear,"
echo "then press Cmd+D to run Apple Diagnostics (memory, logic board, battery, sensors)."

section "DONE"
echo "Report saved to: $REPORT"
echo "Review warnings: SMART status not 'Verified', battery Condition not 'Normal', <15GB free,"
echo "memory pressure 'critical', secure token DISABLED for any user, repeated loginwindow errors."
