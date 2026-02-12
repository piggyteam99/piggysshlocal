```bash
#!/bin/bash
set -euo pipefail

BASE_DIR="/opt/piggy_tunnel"
CONFIG_FILE="$BASE_DIR/server.conf"
TUNNEL_LIST="$BASE_DIR/tunnels.list"
LOG_FILE="$BASE_DIR/piggy.log"
SCRIPT_PATH="$(realpath "$0")"
SERVICE_NAME="piggy-monitor"

mkdir -p "$BASE_DIR"
touch "$TUNNEL_LIST"

SSH_KEY="/root/.ssh/id_rsa"
SSH_OPTS_COMMON="-N -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ConnectTimeout=10 -o TCPKeepAlive=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IPQoS=throughput"

TUN_DIR="/opt/piggy_tun"
mkdir -p "$TUN_DIR"
TUN_CFG="$TUN_DIR/tun.conf"
TUN_SVC_IRAN="piggy-tun-iran"
TUN_SVC_FOREIGN="piggy-tun-foreign"

TUN_ID="0"
TUN_DEV="tun0"
TUN_FOREIGN_IP="10.66.0.1/30"
TUN_IRAN_IP="10.66.0.2/30"
TUN_MTU_DEFAULT="1400"
TUN_SSH_PORT_DEFAULT="2222"

as_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "❌ لطفاً با root اجرا کن."; exit 1; }; }
ensure_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_install_if_needed() {
  export DEBIAN_FRONTEND=noninteractive
  if ensure_cmd apt-get; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "$@" >/dev/null 2>&1 || true
  fi
}

install_piggy_commands() {
  chmod +x "$SCRIPT_PATH" 2>/dev/null || true

  if [ ! -L "/usr/local/bin/piggyssh" ] || [ "$(readlink -f /usr/local/bin/piggyssh 2>/dev/null || true)" != "$SCRIPT_PATH" ]; then
    echo "🐷 نصب دستور piggyssh..."
    ln -sf "$SCRIPT_PATH" /usr/local/bin/piggyssh
    chmod +x /usr/local/bin/piggyssh
    echo "✅ نصب شد. از این به بعد: piggyssh"
    sleep 1
  fi

  if [ ! -L "/usr/local/bin/piggy" ] || [ "$(readlink -f /usr/local/bin/piggy 2>/dev/null || true)" != "$SCRIPT_PATH" ]; then
    ln -sf "$SCRIPT_PATH" /usr/local/bin/piggy
    chmod +x /usr/local/bin/piggy
  fi
}

log() {
  local max_lines=2000
  if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE")" -gt "$max_lines" ]; then
    tail -n "$max_lines" "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
  fi
  echo "[$(date '+%F %T')] $1" >> "$LOG_FILE"
}

pause() { read -p "Enter برای ادامه..."; }

kill_all_tunnel_processes() {
  pkill -f "ssh .* -L 0\.0\.0\.0:" >/dev/null 2>&1 || true
}

restart_service() {
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
}

install_service() {
  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOL
[Unit]
Description=Piggy Tunnel Manager Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$SCRIPT_PATH --monitor
Restart=always
RestartSec=3
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOL
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
  echo "✅ سرویس piggy-monitor فعال شد."
}

show_logs() {
  clear
  echo "📝 آخرین لاگ‌ها:"
  echo "----------------"
  tail -n 80 "$LOG_FILE" 2>/dev/null || true
  echo
  pause
}

list_tunnels() {
  clear
  echo "📋 لیست تانل‌ها"
  echo "--------------"
  if [ ! -s "$TUNNEL_LIST" ]; then
    echo "(هیچ تانلی ثبت نشده)"
  else
    while IFS=: read -r lport rport; do
      [[ -z "$lport" ]] && continue
      echo "  $lport  ->  $rport"
    done < "$TUNNEL_LIST"
  fi
  echo
  pause
}

remove_tunnel() {
  clear
  echo "➖ حذف تانل"
  echo "-----------"
  if [ ! -s "$TUNNEL_LIST" ]; then
    echo "(هیچ تانلی وجود ندارد)"
    pause
    return
  fi
  nl -w2 -s'. ' "$TUNNEL_LIST"
  echo
  read -p "شماره تانل: " num
  [[ -z "$num" ]] && return
  sed -i "${num}d" "$TUNNEL_LIST"
  restart_service
  echo "✅ حذف شد."
  pause
}

reset_tunnels() {
  clear
  echo "🧹 حذف همه تانل‌ها"
  echo "------------------"
  read -p "مطمئنی؟ (y/n): " confirm
  [[ "$confirm" != "y" ]] && return
  : > "$TUNNEL_LIST"
  kill_all_tunnel_processes
  restart_service
  log "All tunnels reset by user."
  echo "✅ انجام شد."
  pause
}

ensure_server_conf_or_autofill() {
  if [[ ! -f "$CONFIG_FILE" ]] && ip link show "$TUN_DEV" >/dev/null 2>&1; then
    mkdir -p "$BASE_DIR"
    cat >"$CONFIG_FILE" <<EOF
REMOTE_USER='root'
REMOTE_IP='10.66.0.1'
REMOTE_SSH_PORT='${TUN_SSH_PORT_DEFAULT}'
EOF
    log "Auto-created server.conf for tun endpoint 10.66.0.1:${TUN_SSH_PORT_DEFAULT}"
  fi
}

setup_server_manual() {
  clear
  echo "⚙️ تنظیم دستی مقصد (اختیاری)"
  echo "----------------------------"
  read -p "REMOTE_USER [root]: " ru
  read -p "REMOTE_IP (مثلاً 10.66.0.1 یا IP واقعی): " rip
  read -p "REMOTE_SSH_PORT [22]: " rp

  ru="${ru:-root}"
  rp="${rp:-22}"
  [[ -z "$rip" ]] && { echo "❌ IP خالیه"; pause; return; }

  cat >"$CONFIG_FILE" <<EOF
REMOTE_USER='${ru}'
REMOTE_IP='${rip}'
REMOTE_SSH_PORT='${rp}'
EOF
  echo "✅ ذخیره شد: $CONFIG_FILE"
  pause
}

add_tunnel() {
  ensure_server_conf_or_autofill
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ مقصد تنظیم نشده."
    pause
    return
  fi

  clear
  echo "➕ افزودن تانل"
  echo "-------------"
  read -p "Local Port (ایران): " lport
  read -p "Remote Port (خارج): " rport
  [[ -z "$lport" || -z "$rport" ]] && { echo "❌ پورت خالی"; pause; return; }

  if grep -q "^${lport}:" "$TUNNEL_LIST"; then
    echo "❌ این LocalPort قبلاً ثبت شده."
    pause
    return
  fi

  echo "${lport}:${rport}" >> "$TUNNEL_LIST"
  restart_service
  echo "✅ اضافه شد."
  pause
}

monitor_mode() {
  apt_install_if_needed iproute2 netcat-openbsd >/dev/null 2>&1 || true
  log "Piggy Monitor Started."

  while true; do
    if [ ! -f "$TUNNEL_LIST" ]; then sleep 5; continue; fi

    ensure_server_conf_or_autofill
    if [ ! -f "$CONFIG_FILE" ]; then sleep 5; continue; fi

    # shellcheck disable=SC1090
    source "$CONFIG_FILE"

    REMOTE_USER="${REMOTE_USER:-root}"
    REMOTE_IP="${REMOTE_IP:-}"
    REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-22}"

    [[ -z "$REMOTE_IP" ]] && { sleep 5; continue; }

    while IFS=: read -r lport rport; do
      [[ -z "$lport" ]] && continue

      if ss -tln 2>/dev/null | grep -q ":${lport}\b"; then
        continue
      fi

      log "Tunnel $lport is DOWN. Restoring..."
      fuser -k -n tcp "$lport" >/dev/null 2>&1 || true
      pkill -f "ssh.*0\.0\.0\.0:${lport}:127\.0\.0\.1:${rport}" >/dev/null 2>&1 || true

      ssh -i "$SSH_KEY" -p "$REMOTE_SSH_PORT" $SSH_OPTS_COMMON \
        -L "0.0.0.0:${lport}:127.0.0.1:${rport}" \
        "${REMOTE_USER}@${REMOTE_IP}" >/dev/null 2>&1 &

      log "Started ssh -L 0.0.0.0:${lport} -> 127.0.0.1:${rport} via ${REMOTE_IP}:${REMOTE_SSH_PORT}"
      sleep 0.2
    done < "$TUNNEL_LIST"

    sleep 2
  done
}

tun_save_cfg() {
  cat > "$TUN_CFG" <<EOF
REMOTE_HOST='${REMOTE_HOST}'
REMOTE_USER='root'
SSH_PORT='${SSH_PORT}'
SSH_KEY='${SSH_KEY}'
TUN_MTU='${TUN_MTU}'
EOF
  chmod 600 "$TUN_CFG"
}

tun_load_cfg() {
  if [[ -f "$TUN_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$TUN_CFG" 2>/dev/null || true
  fi
}

iran_setup_tun_and_autoconfig_piggy() {
  clear
  echo "🔧 ساخت SSH TUN ایران → خارج"
  echo "----------------------------"
  tun_load_cfg

  read -p "IP واقعی سرور خارج [${REMOTE_HOST:-}]: " inp
  [[ -n "$inp" ]] && REMOTE_HOST="$inp"
  [[ -z "${REMOTE_HOST:-}" ]] && { echo "❌ IP خالی"; pause; return; }

  SSH_PORT="${SSH_PORT:-22}"
  read -p "پورت SSH روی IP واقعی خارج [${SSH_PORT}]: " inp
  [[ -n "$inp" ]] && SSH_PORT="$inp"

  TUN_MTU="${TUN_MTU:-$TUN_MTU_DEFAULT}"
  read -p "MTU [${TUN_MTU}]: " inp
  [[ -n "$inp" ]] && TUN_MTU="$inp"
  TUN_MTU="${TUN_MTU:-$TUN_MTU_DEFAULT}"

  apt_install_if_needed openssh-client sshpass iproute2 >/dev/null 2>&1 || true

  mkdir -p /root/.ssh
  if [[ ! -f "$SSH_KEY" ]]; then
    echo "⚠️ ساخت کلید RSA..."
    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -q
  fi

  read -s -p "پسورد SSH سرور خارج (فقط همین یکبار): " REMOTE_PASS
  echo

  PUB_KEY="$(cat "${SSH_KEY}.pub")"

  echo "⏳ نصب کلید روی سرور خارج..."
  sshpass -p "$REMOTE_PASS" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@${REMOTE_HOST}" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && \
     grep -qxF '$PUB_KEY' ~/.ssh/authorized_keys || echo '$PUB_KEY' >> ~/.ssh/authorized_keys"

  echo "✅ کلید نصب شد."

  tun_save_cfg

  cat >"/etc/systemd/system/${TUN_SVC_IRAN}.service" <<EOL
[Unit]
Description=Piggy SSH TUN (IRAN) keep ${TUN_DEV} up
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=10

ExecStartPre=/bin/bash -lc 'ip tuntap add dev ${TUN_DEV} mode tun 2>/dev/null || true; ip link set ${TUN_DEV} up 2>/dev/null || true; ip addr replace ${TUN_IRAN_IP} dev ${TUN_DEV} 2>/dev/null || true; ip link set ${TUN_DEV} mtu ${TUN_MTU} 2>/dev/null || true; true'

ExecStart=/usr/bin/ssh -i ${SSH_KEY} -p ${SSH_PORT} \\
  -o BatchMode=yes -o ConnectTimeout=10 \\
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
  -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \\
  -o TCPKeepAlive=yes -o ExitOnForwardFailure=yes -o IPQoS=throughput \\
  -w ${TUN_ID}:${TUN_ID} root@${REMOTE_HOST} \\
  "ip link set ${TUN_DEV} up; ip addr replace ${TUN_FOREIGN_IP} dev ${TUN_DEV}; ip link set ${TUN_DEV} mtu ${TUN_MTU}"

ExecStartPost=/bin/bash -lc 'for i in {1..80}; do ip link show ${TUN_DEV} >/dev/null 2>&1 && break; sleep 0.25; done; ip link set ${TUN_DEV} up 2>/dev/null || true; ip addr replace ${TUN_IRAN_IP} dev ${TUN_DEV} 2>/dev/null || true; ip link set ${TUN_DEV} mtu ${TUN_MTU} 2>/dev/null || true; true'

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable --now "${TUN_SVC_IRAN}.service" >/dev/null 2>&1 || true
  systemctl restart "${TUN_SVC_IRAN}.service" >/dev/null 2>&1 || true

  echo "✅ سرویس TUN سمت ایران فعال شد."

  cat >"$CONFIG_FILE" <<EOF
REMOTE_USER='root'
REMOTE_IP='10.66.0.1'
REMOTE_SSH_PORT='${TUN_SSH_PORT_DEFAULT}'
EOF

  echo "✅ مقصد Piggy تنظیم شد: root@10.66.0.1:${TUN_SSH_PORT_DEFAULT}"

  if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    install_service
  else
    restart_service
  fi

  echo
  echo "تست:"
  echo "ssh -i /root/.ssh/id_rsa -p ${TUN_SSH_PORT_DEFAULT} root@10.66.0.1 \"echo OK\""
  echo
  pause
}

iran_tun_status() {
  clear
  echo "📡 وضعیت TUN (ایران)"
  echo "---------------------"
  ip a show "$TUN_DEV" 2>/dev/null || echo "tun0 موجود نیست."
  echo
  ping -c 2 10.66.0.1 2>/dev/null || true
  echo
  systemctl status "$TUN_SVC_IRAN" --no-pager 2>/dev/null || true
  pause
}

foreign_prepare_sshd_for_tun() {
  apt_install_if_needed iproute2 openssh-server >/dev/null 2>&1 || true

  local SSHD_CFG="/etc/ssh/sshd_config"
  if [[ -f "$SSHD_CFG" ]]; then
    if grep -qiE '^\s*PermitTunnel\s+' "$SSHD_CFG"; then
      sed -i 's/^\s*PermitTunnel\s\+.*/PermitTunnel yes/I' "$SSHD_CFG"
    else
      echo "PermitTunnel yes" >> "$SSHD_CFG"
    fi
  fi

  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  echo "✅ PermitTunnel فعال شد."
}

foreign_install_tun_keepalive() {
  clear
  echo "🧩 ساخت/فعال‌سازی tun0 سمت خارج"
  echo "-------------------------------"
  read -p "MTU (Enter=پیشفرض ${TUN_MTU_DEFAULT}): " m
  local mtu="${m:-$TUN_MTU_DEFAULT}"

  cat >"/etc/systemd/system/${TUN_SVC_FOREIGN}.service" <<EOL
[Unit]
Description=Piggy TUN (FOREIGN) keep ${TUN_DEV} up
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/bash -lc 'mkdir -p /run/sshd; chmod 0755 /run/sshd; ip tuntap add dev ${TUN_DEV} mode tun 2>/dev/null || true; ip link set ${TUN_DEV} up; ip addr replace ${TUN_FOREIGN_IP} dev ${TUN_DEV}; ip link set ${TUN_DEV} mtu ${mtu}; true'
ExecStop=/bin/bash -lc 'ip link set ${TUN_DEV} down 2>/dev/null || true; true'

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable --now "${TUN_SVC_FOREIGN}.service" >/dev/null 2>&1 || true
  systemctl restart "${TUN_SVC_FOREIGN}.service" >/dev/null 2>&1 || true

  echo "✅ tun0 آماده شد: ${TUN_FOREIGN_IP} (MTU ${mtu})"
  pause
}

foreign_install_tun_only_sshd() {
  clear
  echo "🛡️ SSH فقط روی tun0 (10.66.0.1:${TUN_SSH_PORT_DEFAULT})"
  echo "-----------------------------------------------"

  local CFG="/etc/ssh/sshd_config_tun"
  local SVC="/etc/systemd/system/sshd-tun.service"

  mkdir -p /run/sshd
  chmod 0755 /run/sshd

  cat >"$CFG" <<EOF
Port ${TUN_SSH_PORT_DEFAULT}
ListenAddress 10.66.0.1

Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
UsePAM yes

AllowTcpForwarding yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 10
ClientAliveCountMax 3
MaxAuthTries 3
LoginGraceTime 20
EOF

  /usr/sbin/sshd -t -f "$CFG"

  cat >"$SVC" <<EOF
[Unit]
Description=OpenSSH (TUN only) 10.66.0.1:${TUN_SSH_PORT_DEFAULT}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/sshd -D -e -f $CFG
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now sshd-tun.service
  systemctl restart sshd-tun.service

  echo "✅ sshd-tun فعال شد."
  ss -tlnp | grep ":${TUN_SSH_PORT_DEFAULT}" || true
  pause
}

foreign_change_main_ssh_port() {
  clear
  echo "🔁 تغییر پورت SSH اصلی سرور خارج"
  echo "--------------------------------"
  echo "⚠️ بعد از تغییر، با پورت جدید وصل شو."
  echo

  local SSHD_CFG="/etc/ssh/sshd_config"
  [[ -f "$SSHD_CFG" ]] || { echo "❌ فایل $SSHD_CFG پیدا نشد."; pause; return; }

  local current_port
  current_port="$(awk '
    BEGIN{IGNORECASE=1}
    $1 ~ /^Port$/ {print $2; exit}
  ' "$SSHD_CFG" 2>/dev/null || true)"
  current_port="${current_port:-22}"

  read -p "پورت جدید [فعلی: ${current_port}]: " new_port
  new_port="${new_port:-$current_port}"

  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
    echo "❌ پورت نامعتبر."
    pause
    return
  fi

  cp -a "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%F_%H%M%S)" 2>/dev/null || true

  if grep -qiE '^\s*Port\s+' "$SSHD_CFG"; then
    sed -i -E "s/^\s*Port\s+.*/Port ${new_port}/I" "$SSHD_CFG"
  else
    echo "Port ${new_port}" >> "$SSHD_CFG"
  fi

  if ensure_cmd ufw; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
      ufw allow "${new_port}/tcp" >/dev/null 2>&1 || true
    fi
  fi

  if /usr/sbin/sshd -t -f "$SSHD_CFG" 2>/dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  else
    echo "❌ کانفیگ sshd مشکل دارد. ریستور می‌کنم..."
    local last_bak
    last_bak="$(ls -1t "${SSHD_CFG}.bak."* 2>/dev/null | head -n1 || true)"
    if [[ -n "$last_bak" ]]; then
      cp -a "$last_bak" "$SSHD_CFG" || true
      systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    fi
    pause
    return
  fi

  echo
  echo "✅ انجام شد."
  echo "برای اتصال:"
  echo "ssh -p ${new_port} root@<SERVER_IP>"
  echo
  pause
}

foreign_reset_all() {
  clear
  echo "🧨 پاکسازی کامل (FOREIGN)"
  echo "--------------------------"
  echo "⚠️ تغییر پورت SSH اصلی دست نمی‌خورد."
  echo
  read -p "مطمئنی؟ (y/n): " confirm
  [[ "${confirm:-n}" != "y" ]] && return

  systemctl stop "${TUN_SVC_FOREIGN}.service" >/dev/null 2>&1 || true
  systemctl disable "${TUN_SVC_FOREIGN}.service" >/dev/null 2>&1 || true

  systemctl stop "sshd-tun.service" >/dev/null 2>&1 || true
  systemctl disable "sshd-tun.service" >/dev/null 2>&1 || true

  rm -f "/etc/systemd/system/${TUN_SVC_FOREIGN}.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/sshd-tun.service" >/dev/null 2>&1 || true
  rm -f "/etc/ssh/sshd_config_tun" >/dev/null 2>&1 || true

  ip link set "${TUN_DEV}" down >/dev/null 2>&1 || true
  ip link del "${TUN_DEV}" >/dev/null 2>&1 || true

  local SSHD_CFG="/etc/ssh/sshd_config"
  if [[ -f "$SSHD_CFG" ]]; then
    sed -i -E '/^\s*PermitTunnel\s+yes\s*$/Id' "$SSHD_CFG" 2>/dev/null || true
  fi

  if [[ -f /etc/sysctl.conf ]]; then
    sed -i -E '/^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/d' /etc/sysctl.conf 2>/dev/null || true
  fi
  sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

  rm -rf "$BASE_DIR" >/dev/null 2>&1 || true
  rm -rf "$TUN_DIR" >/dev/null 2>&1 || true

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || true

  echo "✅ پاکسازی انجام شد."
  pause
}

foreign_status() {
  clear
  echo "📡 وضعیت خارج"
  echo "-------------"
  ip a show tun0 2>/dev/null || true
  echo
  systemctl status "$TUN_SVC_FOREIGN" --no-pager 2>/dev/null || true
  echo
  systemctl status sshd-tun --no-pager 2>/dev/null || true
  echo
  echo "🔎 پورت‌های شنونده SSH (نمای کلی):"
  ss -tlnp 2>/dev/null | grep -E 'sshd|:22\b|:443\b' || true
  pause
}

menu_iran() {
  while true; do
    clear
    echo "🐷 PIGGY (IRAN) 🐷"
    echo "=================="
    echo "1) ⚙️ تنظیم دستی مقصد (اختیاری)"
    echo "2) ➕ Add Tunnel"
    echo "3) ➖ Remove Tunnel"
    echo "4) 📋 List Tunnels"
    echo "5) 📝 Logs"
    echo "6) 🚀 Install/Restart piggy-monitor"
    echo "7) 🔧 ساخت SSH TUN + ست خودکار مقصد (10.66.0.1:${TUN_SSH_PORT_DEFAULT})"
    echo "8) 📡 وضعیت TUN"
    echo "9) 🧹 Reset all tunnels"
    echo "0) خروج"
    echo "=================="
    read -p "انتخاب: " c
    case "$c" in
      1) setup_server_manual ;;
      2) add_tunnel ;;
      3) remove_tunnel ;;
      4) list_tunnels ;;
      5) show_logs ;;
      6) install_service; pause ;;
      7) iran_setup_tun_and_autoconfig_piggy ;;
      8) iran_tun_status ;;
      9) reset_tunnels ;;
      0) exit 0 ;;
      *) echo "نامعتبر"; sleep 1 ;;
    esac
  done
}

menu_foreign() {
  while true; do
    clear
    echo "🌍 PIGGY (FOREIGN) 🌍"
    echo "====================="
    echo "1) ✅ آماده‌سازی SSH برای TUN"
    echo "2) 🧩 ساخت/فعال‌سازی tun0"
    echo "3) 🛡️ SSH فقط روی tun0 (10.66.0.1:${TUN_SSH_PORT_DEFAULT})"
    echo "4) 🔁 تغییر پورت SSH اصلی"
    echo "5) 🧨 پاکسازی کامل (بجز پورت SSH اصلی)"
    echo "6) 📡 وضعیت"
    echo "0) خروج"
    echo "====================="
    read -p "انتخاب: " c
    case "$c" in
      1) foreign_prepare_sshd_for_tun; pause ;;
      2) foreign_install_tun_keepalive ;;
      3) foreign_install_tun_only_sshd ;;
      4) foreign_change_main_ssh_port ;;
      5) foreign_reset_all ;;
      6) foreign_status ;;
      0) exit 0 ;;
      *) echo "نامعتبر"; sleep 1 ;;
    esac
  done
}

as_root

if [[ "${1:-}" == "--monitor" ]]; then
  monitor_mode
  exit 0
fi

install_piggy_commands

clear
echo "این سرور کدومه؟"
echo "1) 🇮🇷 ایران"
echo "2) 🌍 خارج"
read -p "انتخاب (1/2): " role

case "$role" in
  1) menu_iran ;;
  2) menu_foreign ;;
  *) echo "❌ انتخاب نامعتبر"; exit 1 ;;
esac
```
