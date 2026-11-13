#!/bin/bash
# Removes everything MatrixSys installs.
#   uninstall.sh --system   (as root)  helper, LaunchDaemon, pf anchor rules, helper data and log
#   uninstall.sh --user     (as you)   start-at-login agent, preferences, caches
#   uninstall.sh            (as you)   both: asks for your password for the system part, then offers to delete the app
LABEL=com.matrixsys.helper
ANCHOR=com.apple/250.MatrixSys
system_part() {
  launchctl bootout system/$LABEL 2>/dev/null || true
  pfctl -a "$ANCHOR" -F all 2>/dev/null || true
  # release the pf enable reference the helper took (tokens are listed per process name)
  for t in $(pfctl -s References 2>/dev/null | awk '/com.matrixsys/ {for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) {print $i; break}}'); do pfctl -X "$t" 2>/dev/null || true; done
  rm -f /Library/LaunchDaemons/$LABEL.plist /Library/PrivilegedHelperTools/$LABEL /var/run/$LABEL.sock /var/log/$LABEL.log
  rm -rf "/Library/Application Support/MatrixSys"
  echo "system part removed"
}
user_part() {
  launchctl bootout gui/$(id -u)/com.matrixsys.app 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/com.matrixsys.app.plist"
  defaults delete com.matrixsys.app 2>/dev/null || true
  rm -rf "$HOME/Library/Caches/com.matrixsys.app" "$HOME/Library/Saved Application State/com.matrixsys.app.savedState" "$HOME/Library/HTTPStorages/com.matrixsys.app"
  echo "user part removed"
}
case "${1:-}" in
  --system) system_part ;;
  --user) user_part ;;
  *)
    pkill -x MatrixSys 2>/dev/null || true
    user_part
    echo "Removing the helper needs your administrator password:"
    sudo /bin/bash "$0" --system
    if [ -d /Applications/MatrixSys.app ]; then
      read -r -p "Also move /Applications/MatrixSys.app to the Trash? [y/N] " a
      [ "$a" = y ] && osascript -e 'tell application "Finder" to delete POSIX file "/Applications/MatrixSys.app"' >/dev/null && echo "app moved to the Trash"
    fi
    echo "MatrixSys is uninstalled." ;;
esac
