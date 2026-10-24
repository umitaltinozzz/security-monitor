#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
  printf '%s\n' \
    'Usage:' \
    '  sudo ./install.sh --binary PATH --sha256 HEX' \
    'The binary must match this host Linux architecture and its SHA-256 must match a trusted value.' >&2
}

if [[ $EUID -ne 0 ]]; then
  printf '%s\n' 'install.sh must run as root.' >&2
  exit 1
fi

if [[ $# -ne 4 || $3 != --sha256 ]]; then
  usage
  exit 2
fi

if [[ $1 != --binary ]]; then
  usage
  exit 2
fi

source_value=$2
expected_sha256=${4,,}
if [[ ! $expected_sha256 =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'SHA-256 must contain exactly 64 hexadecimal characters.' >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) printf '%s\n' 'This Linux architecture is not supported.' >&2; exit 1 ;;
esac

temporary_directory=$(mktemp -d /tmp/secmon-agent-install.XXXXXXXX)
trap 'rm -rf -- "$temporary_directory"' EXIT
binary_path=$temporary_directory/secmon-agent

source_path=$(realpath -e -- "$source_value")
if [[ ! -f $source_path ]]; then
  printf '%s\n' 'The supplied agent binary is not a regular file.' >&2
  exit 1
fi
cp -- "$source_path" "$binary_path"

actual_sha256=$(sha256sum -- "$binary_path")
actual_sha256=${actual_sha256%% *}
if [[ ${actual_sha256,,} != "$expected_sha256" ]]; then
  printf '%s\n' 'The agent binary SHA-256 does not match the supplied checksum.' >&2
  exit 1
fi

if ! getent passwd secmon >/dev/null; then
  if command -v useradd >/dev/null; then
    useradd --system --user-group --home-dir /var/lib/secmon --create-home --shell /bin/sh secmon
  elif command -v adduser >/dev/null; then
    adduser -S -D -h /var/lib/secmon -s /bin/sh secmon
  else
    printf '%s\n' 'A supported system user creation utility is required.' >&2
    exit 1
  fi
fi

install -d -o root -g root -m 0755 /etc/secmon /etc/secmon/deployments.d
config_path=/etc/secmon/agent.toml
if [[ -L $config_path || ( -e $config_path && ! -f $config_path ) ]]; then
  printf '%s\n' '/etc/secmon/agent.toml must be a regular file, not a symlink.' >&2
  exit 1
fi
if [[ ! -e $config_path ]]; then
  install -o root -g root -m 0644 /dev/null "$config_path"
fi
chown root:root "$config_path"
chmod 0644 "$config_path"
if [[ -L /usr/local/bin/secmon-agent || ( -e /usr/local/bin/secmon-agent && ! -f /usr/local/bin/secmon-agent ) ]]; then
  printf '%s\n' '/usr/local/bin/secmon-agent must be a regular file, not a symlink.' >&2
  exit 1
fi
install -o root -g root -m 0755 "$binary_path" /usr/local/bin/secmon-agent

printf '%s\n' 'secmon-agent installed at /usr/local/bin/secmon-agent.'
printf '%s\n' 'The collector runs as the SSH account and does not need root or a daemon.'
printf '%s\n' 'Keep Docker access disabled unless you separately approve its privileges.'
