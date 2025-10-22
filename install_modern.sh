#!/usr/bin/env bash
# install_modern.sh — DIDASTORE® XPRESS
# Support: Ubuntu 20.04/22.04/24.04/25.04 & Debian 10/11/12/13
set -euo pipefail

##########################
# ====== KONFIG ======  #
##########################
REPO_BASE="https://raw.githubusercontent.com/Adidastore11/adi2/main"

# Paths di repo lo (boleh lo ganti kalau pindah folder)
REGIST_URL="$REPO_BASE/Regist"
XRAY_CFG_URL="$REPO_BASE/config/config.json"
NGINX_MAIN_URL="$REPO_BASE/config/nginx.conf"
NGINX_XRAY_URL="$REPO_BASE/config/xray.conf"
HAPROXY_URL="$REPO_BASE/config/haproxy.cfg"
DROPBEAR_URL="$REPO_BASE/config/dropbear.conf"
MENU_ZIP_URL="$REPO_BASE/menu/menu.zip"
WS_BIN_URL="$REPO_BASE/files/ws"
WS_SVC_URL="$REPO_BASE/files/ws.service"
UDP_MINI_URL="$REPO_BASE/files/udp-mini"
UDP_SVC1_URL="$REPO_BASE/files/udp-mini-1.service"
UDP_SVC2_URL="$REPO_BASE/files/udp-mini-2.service"
UDP_SVC3_URL="$REPO_BASE/files/udp-mini-3.service"
SLOWDNS_URL="$REPO_BASE/files/nameserver"
OPENVPN_URL="$REPO_BASE/files/openvpn"
PASSWORD_PAM_URL="$REPO_BASE/files/password"
BANNER_URL="$REPO_BASE/files/issue.net"

# GeoDB
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

# Notif Telegram (opsional) — isi kalau mau
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"   # ex: 1626302370
TELEGRAM_BOT_KEY="${TELEGRAM_BOT_KEY:-}"   # ex: 6879615xxx:AAxxxx
TELEGRAM_API="https://api.telegram.org/bot${TELEGRAM_BOT_KEY}/sendMessage"

##########################
# ====== UI/HELPER ==== #
##########################
G="\e[92m"; R="\e[31m"; Y="\e[33m"; C="\e[36m"; N="\e[0m"
ok(){   echo -e "${G}[OK]${N} $*"; }
warn(){ echo -e "${Y}[! ]${N} $*"; }
err(){  echo -e "${R}[ERR]${N} $*" >&2; }
hr(){   echo -e "${Y}----------------------------------------------------------${N}"; }
title(){
  hr
  echo -e "  Author : ${G}DIDASTORE® VPN (XPRESS)${N}"
  echo -e "  Script : ${C}install_modern.sh${N}"
  hr
}
trap 'err "Terjadi error di baris $LINENO"; exit 1' ERR

##########################
# ====== VALIDASI ===== #
##########################
title
[[ $EUID -eq 0 ]] || { err "Jalankan sebagai root"; exit 1; }
arch="$(uname -m)"; [[ "$arch" == "x86_64" ]] || { err "Arsitektur tidak didukung: $arch"; exit 1; }
source /etc/os-release
ok "OS terdeteksi: ${PRETTY_NAME}"

IPV4="$(curl -fsS ipv4.icanhazip.com || true)"
[[ -n "${IPV4:-}" ]] || { err "IP publik tidak terdeteksi"; exit 1; }
ok "IP VPS: $IPV4"

# Cek lisensi (jika file ada)
if curl -fsSL "$REGIST_URL" >/dev/null 2>&1; then
  RAW="$(curl -fsSL "$REGIST_URL")"
  USER_L=$(echo "$RAW" | awk -v ip="$IPV4" '$1==ip {print $2}')
  EXP_L=$(echo "$RAW" | awk -v ip="$IPV4" '$1==ip {print $4}')
  if [[ -n "${USER_L:-}" && -n "${EXP_L:-}" ]]; then
    if [[ "$(date +%F)" > "$EXP_L" ]]; then err "Lisensi expired ($EXP_L)"; exit 1; fi
    ok "Lisensi OK: user=$USER_L, exp=$EXP_L"
  else
    warn "Tidak ada entri lisensi untuk $IPV4 — lanjut."
  fi
else
  warn "Regist file tidak ditemukan — lanjut tanpa cek."
fi

export DEBIAN_FRONTEND=noninteractive

##########################
# ====== PAKET ======== #
##########################
ok "Install paket dasar… (butuh beberapa menit)"
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
  curl wget jq unzip zip tar xz-utils git ca-certificates gnupg lsb-release \
  bash-completion cron netcat-openbsd socat \
  iptables iptables-persistent netfilter-persistent \
  python3 python3-pip \
  nginx haproxy dropbear fail2ban vnstat \
  openvpn easy-rsa

systemctl enable --now netfilter-persistent || true
systemctl enable --now fail2ban || true
ok "Paket dasar terpasang."

##########################
# ====== FOLDER ======= #
##########################
mkdir -p /etc/xray /var/log/xray /var/www/html /usr/local/kyt /usr/local/share/xray /etc/nginx/conf.d
touch /var/log/xray/{access.log,error.log}
chown www-data:www-data /var/log/xray

##########################
# ====== DOMAIN ======= #
##########################
echo -ne "${Y}Masukkan DOMAIN/Subdomain (sudah pointing ke IP VPS): ${N}"
read -r DOMAIN
[[ -n "$DOMAIN" ]] || { err "Domain tidak boleh kosong"; exit 1; }
echo "$DOMAIN" >/etc/xray/domain
ok "Domain: $DOMAIN"

##########################
# ====== SSL ECC ====== #
##########################
ok "Pasang SSL (acme.sh EC-256)…"
systemctl stop nginx || true
systemctl stop haproxy || true
rm -rf /root/.acme.sh
curl -fsSL https://get.acme.sh | sh -s email=admin@"$DOMAIN"
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d "$DOMAIN" --ecc \
  --fullchainpath /etc/xray/xray.crt \
  --keypath      /etc/xray/xray.key
chmod 600 /etc/xray/xray.key
ok "SSL OK."

##########################
# ====== XRAY CORE ==== #
##########################
ok "Install Xray core stable…"
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data

# Ambil config dari repo; kalau gagal, pakai fallback bawaan (aman)
if curl -fsSL "$XRAY_CFG_URL" -o /etc/xray/config.json; then
  ok "Ambil config.json dari repo."
else
  warn "Gagal unduh config.json dari repo — gunakan fallback bawaan."
  cat >/etc/xray/config.json <<'JSON'
{
  "log": {"access": "/var/log/xray/access.log","error": "/var/log/xray/error.log","loglevel": "warning"},
  "inbounds": [
    {"listen":"127.0.0.1","port":10000,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"},"tag":"api"},
    {"listen":"127.0.0.1","port":10001,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"xxx"}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vless"}}},
    {"listen":"127.0.0.1","port":10002,"protocol":"vmess","settings":{"clients":[{"id":"xxx","alterId":0}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vmess"}}},
    {"listen":"127.0.0.1","port":10003,"protocol":"trojan","settings":{"decryption":"none","clients":[{"password":"xxx"}],"udp":true},"streamSettings":{"network":"ws","wsSettings":{"path":"/trojan"}}},
    {"listen":"127.0.0.1","port":10004,"protocol":"shadowsocks","settings":{"clients":[{"method":"aes-128-gcm","password":"xxx"}],"network":"tcp,udp"},"streamSettings":{"network":"ws","wsSettings":{"path":"/ss-ws"}}},
    {"listen":"127.0.0.1","port":10005,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"xxx"}]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"vless-grpc"}}},
    {"listen":"127.0.0.1","port":10006,"protocol":"vmess","settings":{"clients":[{"id":"xxx","alterId":0}]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"vmess-grpc"}}},
    {"listen":"127.0.0.1","port":10007,"protocol":"trojan","settings":{"decryption":"none","clients":[{"password":"xxx"}]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"trojan-grpc"}}},
    {"listen":"127.0.0.1","port":10008,"protocol":"shadowsocks","settings":{"clients":[{"method":"aes-128-gcm","password":"xxx"}],"network":"tcp,udp"},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"ss-grpc"}}}
  ],
  "outbounds":[{"protocol":"freedom","settings":{}},{"protocol":"blackhole","settings":{},"tag":"blocked"}],
  "routing":{"rules":[
    {"type":"field","ip":["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","::1/128","fc00::/7","fe80::/10"],"outboundTag":"blocked"},
    {"inboundTag":["api"],"outboundTag":"api","type":"field"},
    {"type":"field","outboundTag":"blocked","protocol":["bittorrent"]}
  ]},
  "stats":{},
  "api":{"services":["StatsService"],"tag":"api"},
  "policy":{"levels":{"0":{"statsUserDownlink":true,"statsUserUplink":true}},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}}
}
JSON
fi

# Inject UUID kalau config pakai placeholder "xxx"
UUID="$(cat /proc/sys/kernel/random/uuid)"
sed -i "s/\"xxx\"/\"$UUID\"/g" /etc/xray/config.json

# GeoDB
curl -fsSL "$GEOSITE_URL" -o /usr/local/share/xray/geosite.dat
curl -fsSL "$GEOIP_URL"   -o /usr/local/share/xray/geoip.dat

systemctl enable --now xray
ok "Xray OK (UUID: $UUID)."

########################################
# ====== NGINX & HAPROXY REVERSE ===== #
########################################
ok "Siapkan Nginx & HAProxy…"

# Nginx main config
if curl -fsSL "$NGINX_MAIN_URL" -o /etc/nginx/nginx.conf; then
  ok "nginx.conf dari repo dipakai."
else
  warn "nginx.conf repo gagal — pakai fallback bawaan."
  cat >/etc/nginx/nginx.conf <<'NGINX'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 4096; }
http {
  sendfile on; tcp_nopush on; tcp_nodelay on; keepalive_timeout 65; types_hash_max_size 2048;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log  /var/log/nginx/error.log warn;
  include /etc/nginx/conf.d/*.conf;
  server { listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt; ssl_certificate_key /etc/xray/xray.key;
    root /var/www/html;
  }
}
NGINX
fi

# Nginx xray proxy
if curl -fsSL "$NGINX_XRAY_URL" -o /etc/nginx/conf.d/xray.conf; then
  sed -i "s/xxx/$DOMAIN/g" /etc/nginx/conf.d/xray.conf
  ok "xray.conf dari repo dipakai."
else
  warn "xray.conf repo gagal — pakai fallback bawaan."
  cat >/etc/nginx/conf.d/xray.conf <<NGINX
server {
    listen 1010 so_keepalive=on reuseport;
    server_name $DOMAIN;
    client_max_body_size 10M;
    location /vless {
      proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:10001;
    }
    location /vmess {
      proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:10002;
    }
    location /trojan {
      proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:10003;
    }
    location /ss-ws {
      proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:10004;
    }
    location / {
      proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:10015;
    }
}
server {
    listen 1013 http2 so_keepalive=on reuseport;
    server_name $DOMAIN;
    location /vless-grpc { grpc_set_header Host \$host; grpc_pass grpc://127.0.0.1:10005; }
    location /vmess-grpc { grpc_set_header Host \$host; grpc_pass grpc://127.0.0.1:10006; }
    location /trojan-grpc { grpc_set_header Host \$host; grpc_pass grpc://127.0.0.1:10007; }
    location /ss-grpc     { grpc_set_header Host \$host; grpc_pass grpc://127.0.0.1:10008; }
}
NGINX
fi

# HAProxy
mkdir -p /etc/haproxy
if curl -fsSL "$HAPROXY_URL" -o /etc/haproxy/haproxy.cfg; then
  sed -i "s/xxx/$DOMAIN/g" /etc/haproxy/haproxy.cfg
  ok "haproxy.cfg dari repo dipakai."
else
  warn "haproxy.cfg repo gagal — pakai fallback bawaan."
  cat >/etc/haproxy/haproxy.cfg <<'HAP'
global
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048
    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private
defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 60s
    timeout client  300s
    timeout server  300s
frontend http_frontend
    mode tcp
    bind *:80 tfo
    bind *:8080 tfo
    bind *:8880 tfo
    bind *:2080 tfo
    bind *:2082 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    acl is_websocket hdr(Upgrade) -i websocket
    use_backend ws_backend if is_websocket
    default_backend dropbear_backend
frontend https_frontend
    bind *:443 ssl crt /etc/haproxy/hap.pem tfo
    mode tcp
    tcp-request inspect-delay 500ms
    tcp-request content accept if { req.ssl_hello_type 1 }
    acl is_websocket_ssl hdr(Upgrade) -i websocket
    use_backend ws_backend if is_websocket_ssl
    default_backend dropbear_backend
backend dropbear_backend
    mode tcp
    server dropbear_server 127.0.0.1:58080 check
backend ws_backend
    mode tcp
    server ws_server 127.0.0.1:1010 check
HAP
fi
cat /etc/xray/xray.key /etc/xray/xray.crt > /etc/haproxy/hap.pem

systemctl daemon-reload
systemctl enable --now xray nginx haproxy
systemctl restart xray nginx haproxy
ok "Reverse proxy aktif."

########################################
# ====== SSH / DROPBEAR / WS / DLL === #
########################################
ok "Konfigurasi SSH & Dropbear…"
[[ -f /etc/ssh/sshd_config ]] || touch /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config
systemctl enable --now ssh

# Banner
if curl -fsSL "$BANNER_URL" -o /etc/kyt.txt; then
  grep -q "Banner /etc/kyt.txt" /etc/ssh/sshd_config || echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
  systemctl restart ssh || true
fi

# Dropbear
if curl -fsSL "$DROPBEAR_URL" -o /etc/default/dropbear; then
  systemctl enable --now dropbear
else
  warn "dropbear.conf tidak ada — tetap enable dropbear bawaan."
  systemctl enable --now dropbear || true
fi

# ePro WebSocket (ws)
ok "Install WebSocket Proxy (ws)…"
if curl -fsSL "$WS_BIN_URL" -o /usr/bin/ws && curl -fsSL "$WS_SVC_URL" -o /etc/systemd/system/ws.service; then
  chmod +x /usr/bin/ws
  systemctl enable --now ws || true
else
  warn "ws binary/service tidak ditemukan — dilewati."
fi

# SlowDNS
warn "Install SlowDNS (opsional)…"
if curl -fsSL "$SLOWDNS_URL" -o /tmp/nameserver; then
  chmod +x /tmp/nameserver; bash /tmp/nameserver || true
else
  warn "Installer SlowDNS tidak ada — dilewati."
fi

# UDP limiter
ok "Aktifkan UDP limiter (opsional)…"
if curl -fsSL "$UDP_MINI_URL" -o /usr/local/kyt/udp-mini; then
  chmod +x /usr/local/kyt/udp-mini
  for i in 1 2 3; do
    curl -fsSL "$(eval echo \$UDP_SVC${i}_URL)" -o "/etc/systemd/system/udp-mini-${i}.service" || true
    systemctl enable --now "udp-mini-${i}.service" || true
  done
else
  warn "Binary udp-mini tidak ditemukan — dilewati."
fi

# OpenVPN
warn "Install OpenVPN (opsional)…"
if curl -fsSL "$OPENVPN_URL" -o /root/openvpn; then
  chmod +x /root/openvpn; bash /root/openvpn || true
  systemctl enable --now openvpn || true
  systemctl enable --now openvpn-server@server-tcp || true
  systemctl enable --now openvpn-server@server-udp || true
else
  warn "Installer OpenVPN tidak ada — dilewati."
fi

########################################
# ====== MENU, CRON, PAM PASSWORD ==== #
########################################
ok "Pasang menu & PAM password rules…"
# PAM password (kalau ada)
curl -fsSL "$PASSWORD_PAM_URL" -o /etc/pam.d/common-password || true
chmod 644 /etc/pam.d/common-password || true

# Menu zip (kalau ada). Kalau nggak ada, bikin menu dummy.
if curl -fsSL "$MENU_ZIP_URL" -o /root/menu.zip; then
  unzip -o /root/menu.zip -d /usr/local/sbin >/dev/null 2>&1 || warn "menu.zip gagal diekstrak"
  chmod +x /usr/local/sbin/* || true
  rm -f /root/menu.zip
else
  warn "menu.zip tidak ada — buat menu dummy."
  cat >/usr/local/sbin/menu <<'SH'
#!/usr/bin/env bash
echo "────────── MENU (Dummy) ──────────"
echo "1) Cek status: systemctl status xray nginx haproxy"
echo "2) Log Xray  : tail -f /var/log/xray/access.log"
echo "3) Restart   : systemctl restart xray nginx haproxy"
echo "4) UUID      : grep -oE '\"id\": \"[^\"]+\"' /etc/xray/config.json | head -1"
echo "──────────────────────────────────"
SH
  chmod +x /usr/local/sbin/menu
fi

# Tampilkan menu tiap login root
cat >/root/.profile <<'EOF'
if [ -f ~/.bashrc ]; then . ~/.bashrc; fi
mesg n || true
menu
EOF
chmod 644 /root/.profile

# Cron minimal
echo '*/20 * * * * root /usr/local/sbin/clearlog 2>/dev/null || true' >/etc/cron.d/clearlogs
echo '2 0 * * * root /usr/local/sbin/xp 2>/dev/null || true'      >/etc/cron.d/xp_all
systemctl restart cron || true

########################################
# ====== NOTIF TELEGRAM (ops) ======== #
########################################
if [[ -n "${TELEGRAM_CHAT_ID}" && -n "${TELEGRAM_BOT_KEY}" ]]; then
  DOMAIN_SHOW="$(cat /etc/xray/domain)"
  TEXT="
<b>⚡ AUTOSCRIPT INSTALLED ⚡</b>
<code>────────────────────</code>
<code>Domain   :</code> <b>${DOMAIN_SHOW}</b>
<code>IPVPS    :</code> <b>${IPV4}</b>
<code>UUID     :</code> <b>${UUID}</b>
<code>────────────────────</code>
<i>Notification from install_modern.sh</i>"
  curl -s --max-time 10 -d "chat_id=${TELEGRAM_CHAT_ID}&disable_web_page_preview=1&text=${TEXT}&parse_mode=html" "${TELEGRAM_API}" >/dev/null || true
  ok "Notifikasi Telegram dikirim."
else
  warn "TELEGRAM_CHAT_ID / TELEGRAM_BOT_KEY kosong — skip notif."
fi

##########################
# ====== RINGKAS ====== #
##########################
hr
ok "Semua komponen terpasang."
echo -e "${C}Domain  :${N} $DOMAIN"
echo -e "${C}UUID    :${N} $UUID"
echo -e "${C}Cert    :${N} /etc/xray/xray.crt"
echo -e "${C}Key     :${N} /etc/xray/xray.key"
hr
warn "Reboot direkomendasikan. Reboot otomatis dalam 10 detik…"
sleep 10
reboot
