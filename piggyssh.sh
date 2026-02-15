#!/usr/bin/env bash
set -euo pipefail

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"

SERVICE_NAME="piggy-ssh-tun0.service"
CONF_DIR="/etc/piggy"
CONF_FILE="$CONF_DIR/ssh-tun0.conf"
SYSCTL_FILE="/etc/sysctl.d/99-piggy-ssh-tun.conf"
UP_SCRIPT="/usr/local/sbin/piggy-ssh-tun-up"
DOWN_SCRIPT="/usr/local/sbin/piggy-ssh-tun-down"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}"

TUN_ID="0"
TUN_DEV="tun0"

LOG_FILE="/var/log/piggy-ssh-tun-install.log"
AUTOSSH_LOG="/var/log/piggy-ssh-tun0.log"

# FOREIGN watcher
FOREIGN_KEEP_SCRIPT="/usr/local/sbin/piggy-tun0-foreign-keep"
FOREIGN_KEEP_UNIT="/etc/systemd/system/piggy-tun0-foreign-keep.service"
FOREIGN_KEEP_SERVICE="piggy-tun0-foreign-keep.service"

# IRAN watcher
IRAN_KEEP_SCRIPT="/usr/local/sbin/piggy-tun0-iran-keep"
IRAN_KEEP_UNIT="/etc/systemd/system/piggy-tun0-iran-keep.service"
IRAN_KEEP_SERVICE="piggy-tun0-iran-keep.service"

# CLI command: piggyssh
CLI_SCRIPT="/usr/local/sbin/piggyssh-manager"
CLI_CMD="/usr/local/bin/piggyssh"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}✗ لطفاً با root اجرا کن (sudo -i)${NC}"
    exit 1
  fi
}

ts() { date +"%Y-%m-%d %H:%M:%S"; }

run_live() {
  local cmd="$1"
  echo -e "${YELLOW}[$(ts)] ▶ ${cmd}${NC}"
  bash -lc "$cmd" 2>&1 | stdbuf -oL -eL awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }' | tee -a "$LOG_FILE"
}

read_nonempty() {
  local prompt="$1"
  local var=""
  while true; do
    read -r -p "$prompt" var
    var="${var//$'\t'/}"
    var="${var//$'\r'/}"
    [[ -n "${var// }" ]] && { echo "${var}"; return 0; }
    echo "خالی نباشه."
  done
}

ask_yes_no() {
  local prompt="$1"
  local ans=""
  while true; do
    read -r -p "$prompt (y/n): " ans
    ans="${ans,,}"
    [[ "$ans" == "y" || "$ans" == "yes" ]] && { echo "y"; return 0; }
    [[ "$ans" == "n" || "$ans" == "no"  ]] && { echo "n"; return 0; }
  done
}

load_conf() {
  [[ -f "$CONF_FILE" ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF_FILE"
  return 0
}

install_prereqs() {
  echo -e "${YELLOW}[*] نصب/بررسی پیش‌نیازها (نمایش زنده + لاگ): ${LOG_FILE}${NC}"
  touch "$LOG_FILE" || true
  chmod 600 "$LOG_FILE" 2>/dev/null || true
  export DEBIAN_FRONTEND=noninteractive

  run_live "apt-get update -y"
  run_live "apt-get install -y iproute2 kmod coreutils openssh-client openssh-server autossh sshpass"

  run_live "modprobe tun || true"
  run_live "mkdir -p /dev/net || true"
  run_live "[[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200 || true"
  run_live "chmod 600 /dev/net/tun || true"

  echo -e "${GREEN}[+] پیش‌نیازها OK${NC}"
}

apply_sysctl() {
  echo -e "${YELLOW}[*] اعمال sysctl (rp_filter off + ip_forward)...${NC}"
  cat >"$SYSCTL_FILE" <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl --system 2>&1 | tee -a "$LOG_FILE" || true
  echo -e "${GREEN}[+] sysctl اعمال شد${NC}"
}

gen_auto_subnet_30() {
  local a="$1"
  local b="$2"
  local s=""
  if [[ "$a" < "$b" ]]; then s="${a}|${b}"; else s="${b}|${a}"; fi
  local hex
  hex="$(printf "%s" "$s" | sha256sum | awk '{print $1}')"
  local bx="${hex:0:2}" by="${hex:2:2}" bz="${hex:4:2}"
  local x=$((16#$bx)) y=$((16#$by)) z=$((16#$bz))
  x=$(( (x % 254) + 1 ))
  y=$(( (y % 254) + 1 ))
  z=$(( (z % 252) ))
  z=$(( (z / 4) * 4 ))
  echo "10.${x}.${y}.${z}"
}

pick_fast_cipher() {
  echo "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr"
}

make_key_tag() {
  local local_public="${1:-unknown}"
  echo "piggy-ssh-tun0-${local_public}"
}

ensure_dedicated_key() {
  local key_path="$1"
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  if [[ ! -f "$key_path" ]]; then
    echo -e "${YELLOW}[*] ساخت کلید اختصاصی Piggy برای این تونل: ${key_path}${NC}"
    ssh-keygen -t ed25519 -N "" -f "$key_path" 2>&1 | tee -a "$LOG_FILE"
  fi
  chmod 600 "$key_path" 2>/dev/null || true
  chmod 644 "${key_path}.pub" 2>/dev/null || true
}

cleanup_known_hosts_entry() {
  local host="$1" port="$2"
  ssh-keygen -R "$host" >/dev/null 2>&1 || true
  ssh-keygen -R "[$host]:$port" >/dev/null 2>&1 || true
}

save_config() {
  local ROLE="$1" LOCAL_PUBLIC="$2" PEER_PUBLIC="$3" REMOTE_HOST="$4" REMOTE_PORT="$5" REMOTE_USER="$6" BASE_NET="$7" LOCAL_CIDR="$8" PEER_IP="$9" KEY_PATH="${10}" KEY_TAG="${11}"
  mkdir -p "$CONF_DIR"
  cat >"$CONF_FILE" <<EOF
ROLE="${ROLE}"
LOCAL_PUBLIC="${LOCAL_PUBLIC}"
PEER_PUBLIC="${PEER_PUBLIC}"
REMOTE_HOST="${REMOTE_HOST}"
REMOTE_PORT="${REMOTE_PORT}"
REMOTE_USER="${REMOTE_USER}"
BASE_NET="${BASE_NET}"
TUN_LOCAL_CIDR="${LOCAL_CIDR}"
TUN_PEER_IP="${PEER_IP}"
TUN_ID="${TUN_ID}"
TUN_DEV="${TUN_DEV}"
FAST_CIPHERS="$(pick_fast_cipher)"
KEY_PATH="${KEY_PATH}"
KEY_TAG="${KEY_TAG}"
EOF
  chmod 600 "$CONF_FILE"
  echo -e "${GREEN}[+] کانفیگ ذخیره شد: ${CONF_FILE}${NC}"
}

first_time_key_push_password() {
  local remote_user="$1" remote_host="$2" remote_port="$3" remote_pass="$4" key_path="$5" key_tag="$6"
  ensure_dedicated_key "$key_path"

  # prevent hostkey mismatch issues between old/new servers
  cleanup_known_hosts_entry "$remote_host" "$remote_port"

  echo -e "${YELLOW}[*] بار اول: انتقال کلید با پسورد (sshpass) ...${NC}"
  sshpass -p "$remote_pass" ssh -p "$remote_port" -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=/root/.ssh/known_hosts \
    "${remote_user}@${remote_host}" "echo OK" 2>&1 | tee -a "$LOG_FILE"

  # Add key with a clear tag so we can remove it later (from FOREIGN side)
  local pub
  pub="$(cat "${key_path}.pub")"
  sshpass -p "$remote_pass" ssh -p "$remote_port" -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=/root/.ssh/known_hosts \
    "${remote_user}@${remote_host}" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && grep -qF '${pub}' ~/.ssh/authorized_keys || echo '${pub} ${key_tag}' >> ~/.ssh/authorized_keys" \
    2>&1 | tee -a "$LOG_FILE"

  echo -e "${GREEN}[+] کلید منتقل شد. از این به بعد بدون پسورد وصل میشه.${NC}"
}

ensure_remote_permit_tunnel() {
  echo -e "${YELLOW}[*] تنظیم PermitTunnel روی سرور...${NC}"
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || { echo -e "${RED}[-] sshd_config پیدا نشد${NC}"; return 0; }

  cp -a "$cfg" "${cfg}.bak.$(date +%Y%m%d%H%M%S)" 2>&1 | tee -a "$LOG_FILE" || true

  if grep -qiE '^\s*PermitTunnel\s+' "$cfg"; then
    sed -i 's/^\s*PermitTunnel\s\+.*/PermitTunnel yes/I' "$cfg"
  else
    printf "\nPermitTunnel yes\n" >>"$cfg"
  fi

  systemctl restart ssh 2>&1 | tee -a "$LOG_FILE" || systemctl restart sshd 2>&1 | tee -a "$LOG_FILE" || true
  echo -e "${GREEN}[+] sshd ریستارت شد و PermitTunnel فعال شد.${NC}"
}

write_up_down_scripts() {
  cat >"$UP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/piggy/ssh-tun0.conf"
[[ -f "$CONF" ]] || { echo "Missing $CONF"; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

modprobe tun 2>/dev/null || true
mkdir -p /dev/net 2>/dev/null || true
[[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200 2>/dev/null || true
chmod 600 /dev/net/tun 2>/dev/null || true

KEY_PATH="${KEY_PATH:-/root/.ssh/piggyssh_tun0_ed25519}"

SSH_OPTS=(
  -p "$REMOTE_PORT"
  -i "$KEY_PATH"
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile=/root/.ssh/known_hosts
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -o TCPKeepAlive=yes
  -o ExitOnForwardFailure=yes
  -o Compression=no
  -o IPQoS=throughput
  -o Tunnel=point-to-point
  -o PermitLocalCommand=no
  -o Ciphers="$FAST_CIPHERS"
)

export AUTOSSH_GATETIME=0
export AUTOSSH_POLL=5
export AUTOSSH_FIRST_POLL=5
export AUTOSSH_LOGFILE=/var/log/piggy-ssh-tun0.log

exec /usr/bin/autossh -M 0 -N -T -w "${TUN_ID}:${TUN_ID}" "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}"
EOF

  cat >"$DOWN_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
TUN_DEV="tun0"
if ip link show "$TUN_DEV" >/dev/null 2>&1; then
  ip link set "$TUN_DEV" down || true
  ip tuntap del dev "$TUN_DEV" mode tun 2>/dev/null || true
  ip link del "$TUN_DEV" 2>/dev/null || true
fi
EOF

  chmod +x "$UP_SCRIPT" "$DOWN_SCRIPT"
}

write_systemd_unit() {
  cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Piggy SSH TUN (tun0) keep-alive via autossh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UP_SCRIPT}
ExecStop=${DOWN_SCRIPT}
Restart=always
RestartSec=2
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
  echo -e "${GREEN}[+] سرویس فعال شد: ${SERVICE_NAME}${NC}"
}

install_keep_service_common() {
  local which="$1" script_path="$2" unit_path="$3" unit_name="$4"
  echo -e "${YELLOW}[*] (${which}) نصب keep-service برای UP کردن tun0 و ست IP...${NC}"

  cat >"$script_path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/piggy/ssh-tun0.conf"
[[ -f "$CONF" ]] || { echo "Missing $CONF"; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

while true; do
  if ip link show "$TUN_DEV" >/dev/null 2>&1; then
    ip link set "$TUN_DEV" up || true
    if ! ip -4 addr show dev "$TUN_DEV" | grep -qF "${TUN_LOCAL_CIDR%/*}"; then
      ip addr flush dev "$TUN_DEV" 2>/dev/null || true
      ip addr add "$TUN_LOCAL_CIDR" dev "$TUN_DEV" || true
    fi
  fi
  sleep 2
done
EOF

  chmod +x "$script_path"

  cat >"$unit_path" <<EOF
[Unit]
Description=Piggy ${which} tun0 keep IP up
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${script_path}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$unit_name" >/dev/null
  systemctl restart "$unit_name" >/dev/null || true
  echo -e "${GREEN}[+] فعال شد: ${unit_name}${NC}"
}

install_cli_piggyssh() {
  echo -e "${YELLOW}[*] نصب دستور piggyssh (برای باز کردن منو)...${NC}"

  install -m 0755 -D "$(realpath "$0")" "$CLI_SCRIPT"

  cat >"$CLI_CMD" <<EOF
#!/usr/bin/env bash
exec "$CLI_SCRIPT" "\$@"
EOF
  chmod +x "$CLI_CMD"

  echo -e "${GREEN}[+] دستور آماده شد: piggyssh${NC}"
}

cleanup_local_network_state() {
  # Kill leftover autossh/ssh sessions for tun0
  pkill -f "autossh.*-w ${TUN_ID}:${TUN_ID}" 2>/dev/null || true
  pkill -f "ssh .* -w ${TUN_ID}:${TUN_ID}" 2>/dev/null || true

  # Drop tun0 if exists
  if ip link show "$TUN_DEV" >/dev/null 2>&1; then
    ip link set "$TUN_DEV" down 2>/dev/null || true
    ip tuntap del dev "$TUN_DEV" mode tun 2>/dev/null || true
    ip link del "$TUN_DEV" 2>/dev/null || true
  fi

  # remove routes pointing to tun0 (best-effort)
  ip route | awk '$0 ~ / dev tun0 / {print $1}' | while read -r r; do
    [[ -n "$r" ]] && ip route del "$r" 2>/dev/null || true
  done
}

# FOREIGN-only: remove piggy key lines from authorized_keys (uses KEY_TAG)
foreign_remove_piggy_keys() {
  local tag="${1:-}"
  local ak="/root/.ssh/authorized_keys"
  [[ -f "$ak" ]] || return 0
  [[ -n "$tag" ]] || return 0

  cp -a "$ak" "${ak}.bak.$(date +%F_%H%M%S)" 2>/dev/null || true
  # delete any line containing our tag (safe & targeted)
  grep -vF "$tag" "$ak" > "${ak}.tmp" 2>/dev/null || true
  mv -f "${ak}.tmp" "$ak" 2>/dev/null || true
  chmod 600 "$ak" 2>/dev/null || true
}

show_status() {
  echo -e "${YELLOW}[*] Service status:${NC}"
  systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1 && echo "enabled: yes" || echo "enabled: no"
  systemctl is-active "$SERVICE_NAME"  >/dev/null 2>&1 && echo "active:  yes" || echo "active:  no"
  echo

  if ip link show "$TUN_DEV" >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Tunnel interface:${NC}"
    ip link show "$TUN_DEV" | sed 's/^/  /'
    echo -e "${YELLOW}[*] Tunnel IP:${NC}"
    ip -br addr show "$TUN_DEV" | sed 's/^/  /'
  else
    echo -e "${RED}[-] ${TUN_DEV} وجود ندارد.${NC}"
  fi

  if [[ -f "$CONF_FILE" ]]; then
    echo
    echo -e "${YELLOW}[*] Saved config:${NC} ${CONF_FILE}"
    sed 's/^/  /' "$CONF_FILE"
  fi

  echo
  echo -e "${YELLOW}[*] autossh log (last 30 lines):${NC}"
  tail -n 30 "$AUTOSSH_LOG" 2>/dev/null | sed 's/^/  /' || true
}

full_remove_local() {
  echo -e "${RED}⚠️ حذف کامل لوکال: سرویس‌ها + فایل‌ها + tun0 + پروسس‌ها پاک می‌شود.${NC}"
  local ok; ok="$(ask_yes_no "مطمئنی؟")"
  [[ "$ok" == "n" ]] && { echo "لغو شد."; return 0; }

  local had_conf="n"
  if load_conf; then had_conf="y"; fi

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$FOREIGN_KEEP_SERVICE" >/dev/null 2>&1 || true
  systemctl disable --now "$IRAN_KEEP_SERVICE" >/dev/null 2>&1 || true

  cleanup_local_network_state

  # Role-specific cleanup
  if [[ "$had_conf" == "y" ]]; then
    if [[ "${ROLE:-}" == "IRAN" ]]; then
      # IRAN: cleanup known_hosts for last remote + delete dedicated key
      if [[ -n "${REMOTE_HOST:-}" && -n "${REMOTE_PORT:-}" ]]; then
        cleanup_known_hosts_entry "$REMOTE_HOST" "$REMOTE_PORT"
      fi
      if [[ -n "${KEY_PATH:-}" ]]; then
        rm -f "$KEY_PATH" "${KEY_PATH}.pub" >/dev/null 2>&1 || true
      fi
    else
      # FOREIGN: remove tagged piggy key line(s) from authorized_keys
      foreign_remove_piggy_keys "${KEY_TAG:-}"
    fi
  fi

  rm -f "$UNIT_FILE" "$UP_SCRIPT" "$DOWN_SCRIPT" "$SYSCTL_FILE" "$CONF_FILE" \
        "$FOREIGN_KEEP_SCRIPT" "$FOREIGN_KEEP_UNIT" \
        "$IRAN_KEEP_SCRIPT" "$IRAN_KEEP_UNIT" \
        "$LOG_FILE" "$AUTOSSH_LOG" >/dev/null 2>&1 || true

  rm -f "$CLI_CMD" "$CLI_SCRIPT" >/dev/null 2>&1 || true

  rmdir "$CONF_DIR" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo -e "${GREEN}[✓] حذف کامل لوکال انجام شد.${NC}"
}

setup_ssh_tun() {
  install_prereqs
  apply_sysctl

  echo
  echo "روی کدوم سرور هستی؟"
  echo "1) سرور ایران (IP داخل تونل = .1)  (Initiator)"
  echo "2) سرور خارج (IP داخل تونل = .2)"
  local choice=""
  while true; do
    read -r -p "انتخاب (1/2): " choice
    [[ "$choice" == "1" || "$choice" == "2" ]] && break
  done

  local ROLE="IRAN"
  [[ "$choice" == "2" ]] && ROLE="FOREIGN"

  echo
  local LOCAL_PUBLIC
  LOCAL_PUBLIC="$(read_nonempty "LOCAL public IP (IP عمومی همین سرور): ")"

  local PEER_PUBLIC
  PEER_PUBLIC="$(read_nonempty "PEER public IP (IP عمومی سرور مقابل): ")"

  local BASE_NET
  BASE_NET="$(gen_auto_subnet_30 "$LOCAL_PUBLIC" "$PEER_PUBLIC")"

  local LOCAL_TUN_IP="" PEER_TUN_IP=""
  if [[ "$ROLE" == "IRAN" ]]; then
    LOCAL_TUN_IP="${BASE_NET%.*}.1"
    PEER_TUN_IP="${BASE_NET%.*}.2"
  else
    LOCAL_TUN_IP="${BASE_NET%.*}.2"
    PEER_TUN_IP="${BASE_NET%.*}.1"
  fi

  local LOCAL_CIDR="${LOCAL_TUN_IP}/30"

  echo
  echo -e "${GREEN}[AUTO] subnet: ${BASE_NET}/30${NC}"
  echo -e "${GREEN}[AUTO] IP این سرور: ${LOCAL_TUN_IP}/30${NC}"
  echo -e "${GREEN}[AUTO] IP سرور مقابل: ${PEER_TUN_IP}${NC}"

  local KEY_PATH="/root/.ssh/piggyssh_tun0_ed25519"
  local KEY_TAG
  KEY_TAG="$(make_key_tag "$LOCAL_PUBLIC")"

  if [[ "$ROLE" == "FOREIGN" ]]; then
    echo
    local do_fix
    do_fix="$(ask_yes_no "PermitTunnel yes رو ست کنم و sshd رو ریستارت کنم؟")"
    [[ "$do_fix" == "y" ]] && ensure_remote_permit_tunnel

    save_config "$ROLE" "$LOCAL_PUBLIC" "$PEER_PUBLIC" "0.0.0.0" "22" "root" "$BASE_NET" "$LOCAL_CIDR" "$PEER_TUN_IP" "$KEY_PATH" "$KEY_TAG"

    install_keep_service_common "FOREIGN" "$FOREIGN_KEEP_SCRIPT" "$FOREIGN_KEEP_UNIT" "$FOREIGN_KEEP_SERVICE"
    install_cli_piggyssh

    echo
    echo -e "${GREEN}[✓] تمام. (FOREIGN) keep-service نصب شد.${NC}"
    echo -e "${YELLOW}[*] تست:${NC} ping -c 3 ${LOCAL_TUN_IP}"
    echo -e "${YELLOW}[*] بعد از برقراری تونل از ایران:${NC} ping -c 3 ${PEER_TUN_IP}"
    echo -e "${YELLOW}[*] منو با دستور زیر:${NC} piggyssh"
    echo -e "${YELLOW}[*] نکته پیشگیری:${NC} مطمئن شو فایروال (ufw/nft) پورت SSH مقصدت رو برای IP ایران جدید باز گذاشته."
    return 0
  fi

  echo
  local REMOTE_HOST
  REMOTE_HOST="$(read_nonempty "SSH مقصد (IP/Domain سرور خارج): ")"
  local REMOTE_PORT
  REMOTE_PORT="$(read_nonempty "SSH پورت مقصد (مثلاً 22): ")"
  local REMOTE_USER
  REMOTE_USER="$(read_nonempty "SSH یوزر مقصد (مثلاً root): ")"

  echo
  echo -e "${YELLOW}[*] بار اول فقط: پسورد برای انتقال کلید${NC}"
  local REMOTE_PASS
  REMOTE_PASS="$(read_nonempty "Password برای بار اول (${REMOTE_USER}@${REMOTE_HOST}): ")"

  first_time_key_push_password "$REMOTE_USER" "$REMOTE_HOST" "$REMOTE_PORT" "$REMOTE_PASS" "$KEY_PATH" "$KEY_TAG"
  save_config "$ROLE" "$LOCAL_PUBLIC" "$PEER_PUBLIC" "$REMOTE_HOST" "$REMOTE_PORT" "$REMOTE_USER" "$BASE_NET" "$LOCAL_CIDR" "$PEER_TUN_IP" "$KEY_PATH" "$KEY_TAG"

  write_up_down_scripts
  write_systemd_unit

  install_keep_service_common "IRAN" "$IRAN_KEEP_SCRIPT" "$IRAN_KEEP_UNIT" "$IRAN_KEEP_SERVICE"
  install_cli_piggyssh

  echo
  echo -e "${GREEN}[✓] تمام. autossh + keep-service فعال شد.${NC}"
  echo -e "${YELLOW}[*] تست:${NC} ping -c 3 ${PEER_TUN_IP}"
  echo -e "${YELLOW}[*] لاگ autossh:${NC} tail -f ${AUTOSSH_LOG}"
  echo -e "${YELLOW}[*] منو با دستور زیر:${NC} piggyssh"
}

menu() {
  while true; do
    echo
    echo -e "${GREEN}=== PIGGY SSH-TUN MANAGER (tun0 over autossh) ===${NC}"
    echo "1) Setup / Reconfigure"
    echo "2) Status"
    echo -e "${RED}3) Full Remove (Local - role aware)${NC}"
    echo "4) Exit"
    read -r -p "Choose [1-4]: " c
    case "$c" in
      1) setup_ssh_tun ;;
      2) show_status ;;
      3) full_remove_local ;;
      4) exit 0 ;;
      *) echo "Invalid." ;;
    esac
  done
}

need_root
menu
