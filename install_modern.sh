#!/bin/bash
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
# ===================
clear
export IP=$(curl -sS icanhazip.com)
clear
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "  Auther : ${green}VPN - DIDASTORE® ${NC}${YELLOW}(${NC} ${green} XPRESS ${NC}${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Architecture Supported (${green}$(uname -m)${NC})"
else
    echo -e "${ERROR} Architecture Not Supported (${YELLOW}$(uname -m)${NC})"
    exit 1
fi

if grep -qi ubuntu /etc/os-release; then
    OS="ubuntu"
elif grep -qi debian /etc/os-release; then
    OS="debian"
else
    echo -e "${ERROR} OS Tidak Didukung"
    exit 1
fi

OS_VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2)
echo -e "${OK} Detected OS: ${green}${OS^} ${OS_VERSION}${NC}"
echo -e "${OK} IP VPS: ${green}${IP}${NC}"
sleep 2

read -p "$(echo -e "Press ${GRAY}[${NC}${green}Enter${NC}${GRAY}]${NC} to start installation")"
clear

if [ "$EUID" -ne 0 ]; then
    echo "Run as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ not supported"
    exit 1
fi

REPO="https://raw.githubusercontent.com/Adidastore11/adi2/main/"
apt install ruby -y >/dev/null 2>&1
gem install lolcat >/dev/null 2>&1
apt install wondershaper -y >/dev/null 2>&1
clear

print_install(){ echo -e "${YELLOW}# $1${NC}"; sleep 1; }
print_success(){ echo -e "${green}# $1 berhasil dipasang${NC}"; }

mkdir -p /etc/xray /var/log/xray /var/lib/kyt >/dev/null 2>&1
touch /var/log/xray/{access.log,error.log}
chown www-data:www-data /var/log/xray

first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_install "Menyiapkan dependencies"
    apt update -y
    apt upgrade -y
    apt install -y curl wget jq git unzip cron bash-completion netfilter-persistent iptables-persistent
    if [[ "$OS" == "ubuntu" ]]; then
        apt install -y nginx haproxy
    elif [[ "$OS" == "debian" ]]; then
        apt install -y nginx haproxy
    fi
    systemctl enable --now nginx
    systemctl enable --now haproxy
    print_success "Nginx dan Haproxy"
}

base_package() {
    print_install "Menginstall Paket Dasar"
    apt install -y zip pwgen openssl socat python3 python3-pip figlet sudo bsd-mailx vnstat openvpn easy-rsa
    apt install -y msmtp-mta ca-certificates lsb-release
    apt install -y build-essential dnsutils jq git screen xz-utils ntpdate chrony
    ntpdate pool.ntp.org
    systemctl enable chronyd
    systemctl restart chronyd
    print_success "Paket Dasar"
}

nginx_install() {
    print_install "Menyiapkan Nginx"
    apt remove --purge nginx nginx-common nginx-full -y >/dev/null 2>&1
    apt install -y nginx >/dev/null 2>&1
    systemctl enable --now nginx
    print_success "Nginx Siap"
}

pasang_domain() {
    echo -e "Pilih Jenis Domain:"
    echo -e "1) Gunakan Domain Sendiri"
    echo -e "2) Gunakan Domain Random Cloudflare"
    read -p "Pilih (1/2): " opt
    if [[ "$opt" == "1" ]]; then
        read -p "Masukkan domain: " domain
        echo "$domain" > /etc/xray/domain
        echo "$domain" > /root/domain
    else
        wget -q ${REPO}files/cf.sh -O cf.sh && chmod +x cf.sh && ./cf.sh && rm -f cf.sh
    fi
    print_success "Domain Tersimpan"
}

pasang_ssl() {
    print_install "Pasang SSL"
    domain=$(cat /etc/xray/domain)
    systemctl stop nginx haproxy >/dev/null 2>&1
    apt install socat -y >/dev/null 2>&1
    curl https://get.acme.sh | sh -s email=admin@$domain >/dev/null 2>&1
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 600 /etc/xray/xray.key
    print_success "SSL OK"
}
make_folder_xray() {
    print_install "Membuat direktori xray dan database"
    rm -rf /etc/{vmess,vless,trojan,shadowsocks,ssh,bot}
    mkdir -p /etc/{vmess,vless,trojan,shadowsocks,ssh,bot}
    mkdir -p /usr/bin/xray /var/www/html
    for i in vmess vless trojan shadowsocks ssh bot; do
        touch /etc/$i/.$i.db
        echo "& plugin Account" >> /etc/$i/.$i.db
    done
    touch /etc/xray/domain /var/log/xray/{access.log,error.log}
    print_success "Direktori Xray Siap"
}

install_xray() {
    print_install "Instal Xray core versi terbaru"
    latest=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version ${latest#v}
    wget -qO /etc/xray/config.json "${REPO}config/config.json"
    domain=$(cat /etc/xray/domain)
    sed -i "s/xxx/$domain/g" /etc/xray/config.json
    systemctl enable --now xray
    print_success "Xray ${latest} Terpasang"
}

config_proxy() {
    print_install "Menyiapkan konfigurasi Nginx dan HAProxy"
    domain=$(cat /etc/xray/domain)
    wget -qO /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -qO /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    sed -i "s/xxx/$domain/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/$domain/g" /etc/nginx/conf.d/xray.conf
    curl -fsSL "${REPO}config/nginx.conf" -o /etc/nginx/nginx.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    systemctl restart nginx haproxy xray
    print_success "Proxy Config Siap"
}

ssh_password() {
    print_install "Menyiapkan SSH Password & rc-local"
    wget -qO /etc/pam.d/common-password "${REPO}files/password"
    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
exit 0
EOF
    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart ssh
    print_success "SSH Password OK"
}

udp_limit() {
    print_install "Mengaktifkan UDP limiter"
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    for i in 1 2 3; do
        wget -q -O /etc/systemd/system/udp-mini-$i.service "${REPO}files/udp-mini-$i.service"
        systemctl enable --now udp-mini-$i.service
    done
    print_success "UDP Limiter OK"
}

slowdns() {
    print_install "Instal modul SlowDNS"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver"
    chmod +x /tmp/nameserver
    bash /tmp/nameserver || true
    print_success "SlowDNS OK"
}

dropbear_install() {
    print_install "Instal Dropbear"
    apt install -y dropbear
    wget -qO /etc/default/dropbear "${REPO}config/dropbear.conf"
    systemctl enable --now dropbear
    print_success "Dropbear OK"
}

vnstat_install() {
    print_install "Instal vnStat bawaan distro"
    apt install -y vnstat
    systemctl enable --now vnstat
    print_success "vnStat OK"
}

openvpn_install() {
    print_install "Instal OpenVPN"
    wget -qO /root/openvpn "${REPO}files/openvpn"
    chmod +x /root/openvpn
    bash /root/openvpn
    systemctl enable --now openvpn-server@server-tcp || true
    systemctl enable --now openvpn-server@server-udp || true
    print_success "OpenVPN OK"
}

fail2ban_install() {
    print_install "Instal Fail2Ban dan banner"
    apt install -y fail2ban
    systemctl enable --now fail2ban
    wget -qO /etc/kyt.txt "${REPO}files/issue.net"
    echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@' /etc/default/dropbear
    print_success "Fail2Ban & Banner OK"
}

epro_install() {
    print_install "Instal WebSocket Proxy ePro"
    wget -qO /usr/bin/ws "${REPO}files/ws"
    wget -qO /usr/bin/tun.conf "${REPO}config/tun.conf"
    wget -qO /etc/systemd/system/ws.service "${REPO}files/ws.service"
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    systemctl enable --now ws
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    print_success "ePro Proxy OK"
}

ins_backup() {
    print_install "Menyiapkan backup"
    apt install -y rclone
    mkdir -p /root/.config/rclone
    wget -qO /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"
    print_success "Backup OK"
}

swap_enable() {
    print_install "Menyiapkan Swap 1G & BBR"
    dd if=/dev/zero of=/swapfile bs=1M count=1024
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    wget -qO /root/bbr.sh "${REPO}files/bbr.sh"
    chmod +x /root/bbr.sh && bash /root/bbr.sh
    print_success "Swap & BBR OK"
}

menu_install() {
    print_install "Memasang menu"
    wget -qO menu.zip "${REPO}menu/menu.zip"
    unzip -o menu.zip -d /usr/local/sbin
    chmod +x /usr/local/sbin/*
    rm -f menu.zip
    cat >/root/.profile <<'EOF'
if [ -f ~/.bashrc ]; then . ~/.bashrc; fi
mesg n || true
menu
EOF
    print_success "Menu OK"
}

cron_setup() {
    print_install "Atur cronjob"
    echo "*/20 * * * * root /usr/local/sbin/clearlog" >/etc/cron.d/logclean
    echo "2 0 * * * root /usr/local/sbin/xp" >/etc/cron.d/xp_all
    echo "0 5 * * * root /sbin/reboot" >/etc/cron.d/daily_reboot
    echo "*/2 * * * * root /usr/local/sbin/limit-ip" >/etc/cron.d/limit_ip
    echo "*/2 * * * * root /usr/bin/limit-ip" >/etc/cron.d/limit_ip2
    systemctl restart cron
    print_success "Cron OK"
}
restart_all() {
    print_install "Restart semua service"
    systemctl daemon-reload
    for svc in nginx haproxy xray ssh dropbear openvpn cron ws fail2ban netfilter-persistent; do
        systemctl enable --now $svc >/dev/null 2>&1
    done
    systemctl restart nginx haproxy xray ws cron ssh dropbear fail2ban
    print_success "Semua Service Aktif"
}

notif_telegram() {
    print_install "Kirim notifikasi ke Telegram"
    MYIP=$(curl -sS ipv4.icanhazip.com)
    izinsc="${REPO}Regist"
    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}')
    expx=$(curl -s $izinsc | grep $MYIP | awk '{print $3}')
    domain=$(cat /etc/xray/domain)
    CHATID="1626302370"
    KEY="6879615968:AAErYxZHEnmqystuGFD2Xl5R-l9Mwh-_plo"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TEXT="
<b>⚡ AUTOSCRIPT INSTALLED ⚡</b>
<code>────────────────────</code>
<code>User     :</code> <b>$username</b>
<code>Domain   :</code> <b>$domain</b>
<code>IPVPS    :</code> <b>$MYIP</b>
<code>Expired  :</code> <b>$expx</b>
<code>────────────────────</code>
<i>Automatic Notification from install_modern.sh</i>"
    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    print_success "Notifikasi Terkirim"
}

finalize() {
    clear
    echo -e "${YELLOW}----------------------------------------------------------${NC}"
    echo -e " ${green}Semua proses instalasi selesai${NC}"
    echo -e "${YELLOW}----------------------------------------------------------${NC}"
    echo ""
    domain=$(cat /etc/xray/domain)
    uuid=$(grep -oE '"id": "[^"]+"' /etc/xray/config.json | head -1 | cut -d'"' -f4)
    echo -e "${BLUE}Domain  :${NC} $domain"
    echo -e "${BLUE}UUID    :${NC} $uuid"
    echo -e "${BLUE}SSL CRT :${NC} /etc/xray/xray.crt"
    echo -e "${BLUE}SSL KEY :${NC} /etc/xray/xray.key"
    echo -e "${GREEN}Sukses! VPS akan reboot otomatis dalam 10 detik...${NC}"
    sleep 10
    reboot
}

main_install() {
    first_setup
    base_package
    nginx_install
    make_folder_xray
    pasang_domain
    pasang_ssl
    install_xray
    config_proxy
    ssh_password
    udp_limit
    slowdns
    dropbear_install
    vnstat_install
    openvpn_install
    fail2ban_install
    epro_install
    ins_backup
    swap_enable
    menu_install
    cron_setup
    restart_all
    notif_telegram
    finalize
}

main_install
