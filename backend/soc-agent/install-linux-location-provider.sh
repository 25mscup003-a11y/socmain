#!/usr/bin/env bash
# Install the native Linux location stack used by AJNAT. Location collection
# remains disabled until an authenticated company policy enables it.

set -u

if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
  exit 0
fi
if [[ "${SOC_INSTALL_LOCATION_PROVIDER:-true}" == "false" ]]; then
  echo "AJNAT native location-provider setup explicitly disabled"
  exit 0
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Linux location-provider setup must run as root" >&2
  exit 1
fi

have_geoclue_helper() {
  command -v where-am-i >/dev/null 2>&1 \
    || [[ -x /usr/lib/geoclue-2.0/demos/where-am-i ]] \
    || [[ -x /usr/libexec/geoclue-2.0/demos/where-am-i ]]
}

echo "Configuring AJNAT native system location provider..."
if ! have_geoclue_helper; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y geoclue-2.0 geoclue-2-demo
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y geoclue2 geoclue2-demos
  elif command -v yum >/dev/null 2>&1; then
    yum install -y geoclue2 geoclue2-demos
  else
    echo "WARNING: GeoClue must be installed manually on this Linux distribution" >&2
  fi
fi

# ModemManager supplies embedded WWAN/GNSS fixes to GeoClue. gpsd supports
# USB/serial GNSS receivers; both are optional because many desktops have no
# physical GNSS sensor and can still use GeoClue's OS-managed providers.
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y modemmanager gpsd gpsd-clients >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ModemManager gpsd gpsd-clients >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y ModemManager gpsd gpsd-clients >/dev/null 2>&1 || true
fi

for unit in ModemManager.service gpsd.socket; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    systemctl enable --now "$unit" >/dev/null 2>&1 || true
  fi
done

# GNOME stores its Location Services switch in the signed-in user's session,
# not in root's environment. Enable it only when a real desktop session bus is
# present. Other desktops continue to use their own OS permission dialog.
enable_gnome_location_for_uid() {
  local uid="$1" runtime username
  [[ "$uid" =~ ^[0-9]+$ ]] || return 0
  (( uid >= 1000 )) || return 0
  runtime="/run/user/$uid"
  [[ -S "$runtime/bus" ]] || return 0
  username="$(getent passwd "$uid" | cut -d: -f1)"
  [[ -n "$username" ]] || return 0
  command -v runuser >/dev/null 2>&1 || return 0
  runuser -u "$username" -- env \
    XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
    gsettings set org.gnome.system.location enabled true >/dev/null 2>&1 || true
}

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  enable_gnome_location_for_uid "$(id -u "$SUDO_USER" 2>/dev/null || true)"
fi
if command -v loginctl >/dev/null 2>&1; then
  while read -r session_uid _rest; do
    enable_gnome_location_for_uid "$session_uid"
  done < <(loginctl list-users --no-legend 2>/dev/null || true)
fi

if have_geoclue_helper; then
  echo "  OK: GeoClue system location provider is installed"
else
  echo "WARNING: GeoClue helper is unavailable; AJNAT will report degraded GPS coverage" >&2
fi
if compgen -G '/dev/gnss*' >/dev/null \
  || compgen -G '/dev/ttyACM*' >/dev/null \
  || compgen -G '/dev/ttyUSB*' >/dev/null; then
  echo "  OK: a possible local GNSS device is present"
else
  echo "  INFO: no physical GNSS device detected; GeoClue accuracy depends on OS/Wi-Fi providers"
fi
echo "  INFO: coordinates are sent only when GPS policy is enabled and the provider meets its accuracy limit"
