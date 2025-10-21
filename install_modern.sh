#!/usr/bin/env bash
set -euo pipefail

# ====== CONFIG DASAR ======
REPO="https://raw.githubusercontent.com/Adidastore11/adi2/main/"
REGIST_URL="${REPO}Regist"

# ====== WARNA ======
GREEN="\e[92m"; RED="\e[31m"; YELLOW="\e[33m"; BLUE="\e[36m"; NC="\e[0m"
ok(){ echo -e "${GREEN}[OK]${NC} $*"; }
err(){ echo -e "${RED}[ERR]${NC} $*" >&2; }

# ====== CEK ROOT & ARCH ======
if [[ $EUID -ne 0 ]]; then err "Jalankan sebagai root"; exit 1; fi
arch=$(uname -m)
[[ "$arch" == "x86_64" ]] || { err "Arsitektur tidak didukung: $arch"; exit 1; }

# ====== DETEKSI OS ======
source /etc/os-release
OS_ID="$ID"                    # ubuntu/debian
OS_VER="$VERSION_ID"           # 20.04 / 22.04 / 24.04 / 25.04 / 10 / 12 / 13
ok "OS terdeteksi: ${PRETTY_NAME}"

# ====== JARINGAN & INFO VPS ======
IPV4=$(curl -sS ipv4.icanhazip.com || true)
[[ -n "${IPV4:-}" ]] || { err "IP publik tidak terdeteksi"; exit 1; }
ok "IP VPS: $IPV4"

# ====== CEK LISENSI (sesuai format ### user tanggal IP) ======
echo -e "${YELLOW}Cek lisensi...${NC}"
L_RAW="$(curl -fsSL "$REGIST_URL" || true)"
USER_L=$(echo "$L_RAW" | awk -v ip="$IPV4" '$4==ip {print $2}')
EXP_L=$(echo "$L_RAW" | awk -v ip="$IPV4" '$4==ip {print $3}')
if [[ -z "${USER_L:-}" || -z "${EXP_L:-}" ]]; then
  err "IP $IPV4 tidak terdaftar / format Regist tidak sesuai"; exit 1
fi
today="$(date +%F)"
if [[ "$today" > "$EXP_L" ]]; then
  err "Lisensi EXPIRED ($EXP_L)"; exit 1
fi
ok "Lisensi OK: user=$USER_L, expired=$EXP_L"

# ====== PAKET DASAR (kompat modern) ======
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
  curl wget jq socat netcat-openbsd cron bash-completion \
  iptables iptables-persistent netfilter-persistent \
  gnupg ca-certificates lsb-release software-properties-common \
  unzip zip tar xz-utils git bc coreutils rsyslog \
  python3 python3-pip \
  openvpn easy-rsa \
  vnstat fail2ban dropbear \
  nginx haproxy

systemctl enable --now netfilter-persistent || true
systemctl enable --now fail2ban || true
ok "Paket dasar terpasang"

# ====== STRUKTUR FOLDER ======
mkdir -p /etc/xray /var/log/xray /var/www/html /usr/local/kyt
touch /var/log/xray/{access.log,error.log}
chown www-data:www-data /var/log/xray

# ====== INPUT DOMAIN (MANUAL) ======
echo -ne "${YELLOW}Masukkan DOMAIN/Subdomain (sudah pointing ke IP VPS): ${NC}"
read -r DOMAIN
[[ -n "$DOMAIN" ]] || { err "Domain tidak boleh kosong"; exit 1; }
echo "$DOMAIN" >/etc/xray/domain
ok "Domain: $DOMAIN"

# ====== ACME/SSL (standalone, modern) ======
rm -rf /root/.acme.sh
mkdir -p /root/.acme.sh
curl -fsSL https://get.acme.sh | sh -s email=admin@"$DOMAIN"
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
systemctl stop nginx || true
systemctl stop haproxy || true
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d "$DOMAIN" --ecc \
  --fullchainpath /etc/xray/xray.crt \
  --keypath      /etc/xray/xray.key
chmod 600 /etc/xray/xray.key
ok "SSL terpasang"

# ====== XRAY CORE (stable) ======
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data
curl -fsSL "${REPO}config/config.json" -o /etc/xray/config.json
UUID=$(cat /proc/sys/kernel/random/uuid)
sed -i "s/\"xxx\"/\"$UUID\"/g" /etc/xray/config.json
ok "Xray terpasang (UUID: $UUID)"

# ====== NGINX & HAPROXY ======
curl -fsSL "${REPO}config/nginx.conf" -o /etc/nginx/nginx.conf
curl -fsSL "${REPO}config/xray.conf"   -o /etc/nginx/conf.d/xray.conf
sed -i "s/xxx/$DOMAIN/g" /etc/nginx/conf.d/xray.conf

curl -fsSL "${REPO}config/haproxy.cfg" -o /etc/haproxy/haproxy.cfg
cat /etc/xray/xray.key /etc/xray/xray.crt > /etc/haproxy/hap.pem
sed -i "s/xxx/$DOMAIN/g" /etc/haproxy/haproxy.cfg

systemctl daemon-reload
systemctl enable --now xray
systemctl enable --now nginx
systemctl enable --now haproxy
ok "Nginx & Haproxy aktif"

# ====== SSH / DROPBEAR / SLOWDNS / UDP ======
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config
systemctl restart ssh

curl -fsSL "${REPO}config/dropbear.conf" -o /etc/default/dropbear
systemctl enable --now dropbear

curl -fsSL "${REPO}files/nameserver" -o /tmp/nameserver && chmod +x /tmp/nameserver
bash /tmp/nameserver || true

curl -fsSL "${REPO}files/udp-mini" -o /usr/local/kyt/udp-mini
chmod +x /usr/local/kyt/udp-mini
for i in 1 2 3; do
  curl -fsSL "${REPO}files/udp-mini-${i}.service" -o "/etc/systemd/system/udp-mini-${i}.service"
  systemctl enable --now "udp-mini-${i}.service" || true
done

# ====== OpenVPN ======
curl -fsSL "${REPO}files/openvpn" -o /root/openvpn && chmod +x /root/openvpn
bash /root/openvpn
systemctl enable --now openvpn || true
systemctl enable --now openvpn-server@server-tcp || true
systemctl enable --now openvpn-server@server-udp || true

# ====== vnStat ======
apt-get install -y vnstat
systemctl enable --now vnstat || true

# ====== Fail2ban ======
systemctl enable --now fail2ban || true

# ====== Geosite/GeoIP ======
mkdir -p /usr/local/share/xray
curl -fsSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -o /usr/local/share/xray/geosite.dat
curl -fsSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"   -o /usr/local/share/xray/geoip.dat

# ====== Menu ======
curl -fsSL "${REPO}menu/menu.zip" -o /root/menu.zip
unzip -o /root/menu.zip -d /usr/local/sbin && chmod +x /usr/local/sbin/*
rm -f /root/menu.zip
cat >/root/.profile <<'EOF'
if [ -f ~/.bashrc ]; then . ~/.bashrc; fi
mesg n || true
menu
EOF
chmod 644 /root/.profile

# ====== Cron basic ======
cat >/etc/cron.d/clearlogs <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
EOF
systemctl restart cron

# ====== Finish ======
ok "Semua komponen terpasang."
echo -e "${BLUE}Domain   :${NC} $DOMAIN"
echo -e "${BLUE}UUID     :${NC} $UUID"
echo -e "${BLUE}User     :${NC} $USER_L"
echo -e "${BLUE}Expired  :${NC} $EXP_L"
echo -e "${BLUE}Cert     :${NC} /etc/xray/xray.crt"
echo -e "${BLUE}Key      :${NC} /etc/xray/xray.key"
echo -e "${GREEN}Selesai. Reboot direkomendasikan.${NC}"
