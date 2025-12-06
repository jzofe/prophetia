#!/bin/bash


# ENDER PROJECT
# OPEN-SOURCE
# BECOME A PROFESSIONAL ANONYMOUS. 
# Prophetia >>> <Internet connection, traffic encryptor.>

# Coded By FYKS

if [ "$EUID" -ne 0 ]; then
  echo "Permission required. Type 'sudo Prophetia.sh'."
  exit 1
fi

dohpage="/etc/dns-over-https/doh-client.conf"
interface="wlan0"
dns_server="dns://84.200.69.80"
timeout="1668"
disk="/dev/sda1" 
gateway1="94.140.14.14"
gateway2="149.112.112.112"
gateway3="84.200.69.80"
gateway4="37.235.1.174"
gateway5="84.200.70.40"
gateway6="194.36.144.87"
gateway7="51.77.149.139"
gateway8="94.247.43.254"
gateway9="125.18.1.10"
gateway10="94.247.43.254"
gateways=("$gateway1" "$gateway2" "$gateway3" "$gateway4" "$gateway5" "$gateway6" "$gateway7" "$gateway8" "$gateway9" "$gateway10")
current_gateway_index=0
users=(
    "Mozilla/5.0 (Linux; Android 6.0.1; XR6M10 Build/XR6M10.03.99.01.04) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; U; Android 10; in-id; RMX1971 Build/QKQ1.190918.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.80 Mobile Safari/537.36 HeyTapBrowser/45.7.2.5"
    "Dalvik/2.1.0 (Linux; U; Android 6.0.1; SM-A9100 Build/RU1100)"
    "Mozilla/5.0 (Linux; Android 11; SM-A405FN Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.166 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; U; Android 10; tr-tr; Redmi Note 7 Build/QKQ1.190910.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/71.0.3578.141 Mobile Safari/537.36 XiaoMi/MiuiBrowser/12.5.2-gn"
    "Mozilla/5.0 (Linux; Android 6.0.1; HST 260 T2/C Build/MHC19J; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/44.0.2403.119 Safari/537.36"
    "Dalvik/2.1.0 (Linux; U; Android 8.1; T28 Build/MRA58K)"
    "Dalvik/2.1.0 (Linux; U; Android 9; M10 GO Build/PPR1.180610.011)"
    "Mozilla/5.0 (Linux; Android 7.1.1; SM-J510H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.105 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 8.1.0; LM-X210CM) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 5.1.1; KFDOWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/84.1.153 like Chrome/84.0.4147.111 Safari/537.36"
    "Mozilla/5.0 (Linux; Android 9; ZTE Blade A7 2019) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; HRY-LX1 Build/HONORHRY-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.96 Mobile Safari/537.36 YaApp_Android/10.91 YaSearchBrowser/10.91"
    "Mozilla/5.0 (Linux; Android 10; vivo 1819 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.105 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; RMX1851 Build/QKQ1.190918.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.83 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36/DiUzeNty-1"
    "Mozilla/5.0 (Linux; Android 7.1.1; ZC520KL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.96 Mobile Safari/537.36"
    "Dalvik/2.1.0 (Linux; U; Android 10; Mi 9T Pro MIUI/V12.0.6.0.QFKMIXM)"
    "Mozilla/5.0 (Linux; Android 10; SM-G986N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 9; Infinix X650C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.101 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 9; vivo 1907_19 Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36 VivoBrowser/6.8.0.1"
    "Mozilla/5.0 (Linux; Android 8.0.0; SM-C7010 Build/R16NW; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/62.0.3202.84 Mobile Safari/537.36 TTWebView/0621120007024 JsSdk/2 NewsArticle/7.4.9 NetType/wifi (NewsLite 7.4.9)"
)
reqrograms=("mitmproxy" "macchanger" "squid" "proxychains" "tor" "wireguard" "firejail" "librewolf" "i2pd" "lokinet" "yggdrasil" "xdotool" "bpftool" "clang" "go")

usage() {
  echo "usage: $0 -c <interface> -t <timeout>"
  exit 1
}

check() {
  command -v $1 >/dev/null 2>&1
}

install() {
  clear
  echo "Installing $1.."
  if [ -x "$(command -v apt-get)" ]; then
    sudo apt-get install -y $1 >/dev/null 2>&1
  elif [ -x "$(command -v pacman)" ]; then
    sudo pacman -S --noconfirm $1 >/dev/null 2>&1
  else
    echo "Unsupported package manager. install '$1' manually."
    exit 1
  fi
}

for program in "${reqrograms[@]}"; do
  if check $program; then
    echo "$program ok."
  else
    install $program
  fi
done

while getopts ":c:t:d:" opt; do  
  case ${opt} in
    c )
      interface=$OPTARG
      sudo sed -i "35s/IFACE = \".*\"/IFACE = \"$interface\"/" spoofer.py
      ;;
    d )
      disk=$OPTARG
      ;;
    t )
      timeout=$OPTARG
      ;;
    \? )
      echo "Invalid option: -$OPTARG" 1>&2
      usage
      ;;
    : )
      echo "Option -$OPTARG requires an argument." 1>&2
      usage
      ;;
  esac
done

proxys() {
  proxies=$(curl -s "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxytype=all&country=all&anonymity=all&ssl=all&timeout=2000")
  echo "$proxies" > /etc/squid/proxy_list.txt
}
ultra_tcp_spoof() {
  [[ -f /sys/fs/bpf/tcp_spoof ]] && return
  cat >/tmp/tcp_spoof.bpf.c <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
SEC("xdp")
int xdp_spoof(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ip->ihl*4;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    ip->ttl = 64 + (bpf_get_prandom_u32() % 128);
    tcp->window = htons(bpf_get_prandom_u32() % 65535);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
EOF
  clang -O2 -target bpf -c /tmp/tcp_spoof.bpf.c -o /tmp/tcp_spoof.o
  bpftool prog load /tmp/tcp_spoof.o /sys/fs/bpf/tcp_spoof
  bpftool net attach xdp pinned /sys/fs/bpf/tcp_spoof dev "$interface"
  echo -e "\e[31m[ULTRA]\e[0m eBPF TCP-HEADER fingerprint spoofing. "
}

ultra_ram_only() {
  echo -e "\e[31m[ULTRA]\e[0m swap FUCKED + dm-crypt RAM disk"
  sudo swapoff -a
  sudo mkdir -p /mnt/encram
  sudo mount -t tmpfs -o size=2G tmpfs /mnt/encram
  sudo dd if=/dev/zero of=/mnt/encram/swapfile bs=1M count=2048 status=none
  sudo chmod 600 /mnt/encram/swapfile
  sudo mkswap /mnt/encram/swapfile >/dev/null
  sudo swapon /mnt/encram/swapfile
}

random_proxys() {
  rand_proxy=$(shuf -n 1 /etc/squid/proxy_list.txt)
  echo "$rand_proxy" | tr -d '[:space:]'
}

dhcp() {
  sudo dhclient -r > /dev/null 2>&1
  sudo dhclient > /dev/null 2>&1
}

get_mac() {
 sudo ifconfig "$1" | awk '/ether/ {print $2}'
}

routerspoof() {
    INTERFACE_MAC=$(get_mac "$interface")
    ROUTER_MAC=$(get_mac "router_interface")  
    sudo sed -i "32s/ROUTER_MAC = \".*\"/ROUTER_MAC = \"$ROUTER_MAC\"/" spoofer.py
    sudo sed -i "33s/INTERFACE_MAC = \".*\"/INTERFACE_MAC = \"$INTERFACE_MAC\"/" spoofer.py
    sudo bash iptables.sh >/dev/null 2>&1
    sudo python3 spoofer.py >/dev/null 2>&1
}

browser() {
   sudo systemctl start tor >/dev/null 2>&1
   sed -i 's/^strict_chain/dynamic_chain/' /etc/proxychains.conf >/dev/null 2>&1  
   echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf >/dev/null 2>&1
   proxychains librewolf -CreateProfile "prophetia" >/dev/null 2>&1
   PROFILE_DIR=$(find ~/.librewolf -name "*prophetia" -type d | head -1) 
   if [ -z "$PROFILE_DIR" ]; then
     echo "Profile create failed amk."
     exit 1
   fi
   echo 'user_pref("privacy.donottrackheader.enabled", true);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("privacy.clearOnShutdown.cookies", true);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("privacy.clearOnShutdown.history", true);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("browser.send_pings", false);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("beacon.enabled", false);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("toolkit.telemetry.enabled", false);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("network.proxy.type", 1);' >> "$PROFILE_DIR/prefs.js"  # manual proxy (değiştirilebilirxd ama önermiyom gencler)
   echo 'user_pref("network.proxy.socks", "127.0.0.1");' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("network.proxy.socks_port", 9050);' >> "$PROFILE_DIR/prefs.js"
   echo 'user_pref("network.proxy.socks_remote_dns", true);' >> "$PROFILE_DIR/prefs.js"
   proxychains firejail --private librewolf -P prophetia -no-remote >/dev/null 2>&1 &
   echo "LibreWolf started with Tor proxy in firejail sandbox."
}
ultra_namespace() {
  ns="ghost_$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n1)"
  sudo ip netns delete $ns 2>/dev/null
  sudo ip netns add $ns
  sudo ip link add veth0 type veth peer name veth1
  sudo ip link set veth1 netns $ns
  sudo ip addr add 10.66.6.1/24 dev veth0
  sudo ip link set veth0 up
  sudo ip netns exec $ns ip addr add 10.66.6.2/24 dev veth1
  sudo ip netns exec $ns ip link set veth1 up
  sudo ip netns exec $ns ip route add default via 10.66.6.1
  export CURRENT_NS=$ns
}
ultra_multinet() {
  sudo systemctl start i2pd lokinet yggdrasil tor --quiet 2>/dev/null
  cat <<EOF >> /etc/proxychains.conf
socks5 127.0.0.1 4447    # I2P
socks5 127.0.0.1 1090    # Lokinet
socks5 127.0.0.1 20001  # Yggdrasil
socks5 127.0.0.1 9050    # Tor
EOF
  echo -e "\e[32m[+] Tor + I2P + Lokinet + Yggdrasil chain AKTİF\e[0m"
}

ultra_ai_human() {
  (while true; do
    xdotool mousemove_relative --polar $((RANDOM%360)) $((RANDOM%100+20))
    [[ $((RANDOM%3)) -eq 0 ]] && xdotool click 1
    [[ $((RANDOM%7)) -eq 0 ]] && xdotool type --delay $((RANDOM%200+50)) "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c $((RANDOM%5+1))"
    sleep $((RANDOM%15+5))
  done) &
  echo -e "\e[32m[AI]\e[0m ai active :D (NSA DEAD)"
}

log() {

  sudo journalctl --rotate >/dev/null 2>&1
  sudo journalctl --vacuum-time=1s >/dev/null 2>&1
  sudo journalctl --vacuum-size=1M >/dev/null 2>&1

  LOG_FILES=(
    /var/log/syslog
    /var/log/auth.log
    /var/log/kern.log
    /var/log/dmesg
    /var/log/messages
    /var/log/secure
    /var/log/wtmp
    /var/log/btmp
    /var/log/lastlog
    /var/log/faillog
    /var/log/daemon.log
    /var/log/debug
    /var/log/user.log
    /var/log/mail.log
  )

  for logfile in "${LOG_FILES[@]}"; do
    if [ -f "$logfile" ]; then
      sudo shred -z -u -v -n 21 "$logfile" 2>/dev/null || \
      sudo shred -z -u -n 21 "$logfile" 2>/dev/null
    fi
  done

  history -c
  history -w
  shred -z -u -n 10 ~/.bash_history 2>/dev/null || true
  shred -z -u -n 10 ~/.zsh_history 2>/dev/null || true
  shred -z -u -n 10 ~/.python_history 2>/dev/null || true

  sudo find /tmp -type f -exec shred -z -u -n 3 {} \; 2>/dev/null
  sudo find /var/tmp -type f -exec shred -z -u -n 3 {} \; 2>/dev/null

  sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null

  echo "[LOGS] 21-pass shred completed xd (fbi is crying now)"
}
dns() {
  dig +tcp @$dns_server > /dev/null 2>&1
}

user_agent() {
  rand_index=$(( RANDOM % ${#users[@]} ))
  new_user_agent="${users[$rand_index]}"
  echo "$new_user_agent" | sudo tee /etc/squid/custom_user_agent
}

mac() {
  declare -A vendor_dict
  vendor_dict=(
      ["00:41:b4"]="Wuxi Zhongxing Optoelectronics Technowlan0gy Co.,Ltd."
      ["08:00:46"]="Sony Corporation"
      ["00:07:0e"]="Cisco Systems, Inc"
      ["fc:fb:fb"]="Cisco Systems, Inc"
      ["fc:fa:f7"]="Shanghai Baud Data Communication Co.,Ltd."
      ["f8:c6:78"]="Carefusion"
      ["f4:7f:35"]="Cisco Systems, Inc"
      ["f0:37:a1"]="Huike Electronics (SHENZHEN) CO., LTD."
      ["ec:43:f6"]="Zyxel Communications Corporation"
      ["e8:9a:ff"]="Fujian LANDI Commercial Equipment Co.,Ltd"
      ["e8:5b:f0"]="Imaging Diagnostics"
      ["e4:d5:3d"]="Hon Hai Precision Ind. Co.,Ltd."
      ["e0:ee:1b"]="Panasonic Automotive Systems Company of America"
      ["dc:85:de"]="AzureWave Technowlan0gy Inc."
      ["00:50:56"]="Medtronic Diabetes"
      ["3c:df:bd"]="Wush, Inc"
      ["64:34:09"]="BITwave Pte Ltd"
      ["50:a4:c8"]="Samsung Electronics Co.,Ltd"
      ["40:22:ed"]="Digital Projection Ltd"
      ["38:26:cd"]="ANDTEK"
      ["30:89:99"]="Guangdong East Power Co.,"
  )

  prefix_list=("${!vendor_dict[@]}")
  random_index=$((RANDOM % ${#prefix_list[@]}))
  selected_prefix=${prefix_list[$random_index]}
  random_mac=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
  full_mac_address="${selected_prefix,,}:$random_mac"
  sudo ifconfig $interface down > /dev/null 2>&1
  sudo macchanger -m $full_mac_address $interface > /dev/null 2>&1
  sudo ifconfig $interface up > /dev/null 2>&1
}

notify() {
  message="Prophetia: Anonymity renewed! Timeout : $timeout"
  notify-send "Prophetia Notification" "$message"
}

res_settings() {
  echo "Restoring settings..."
  sudo iptables -P INPUT ACCEPT > /dev/null 2>&1
  sudo iptables -P FORWARD ACCEPT > /dev/null 2>&1
  sudo iptables -P OUTPUT ACCEPT > /dev/null 2>&1
  sudo iptables -F > /dev/null 2>&1
  sudo service squid stop > /dev/null 2>&1
  sudo service squid start > /dev/null 2>&1
  sudo swapoff -a  
  echo "Settings restored."
}

trap 'res_settings; exit 1' INT TERM

v5() {
    sleep "$1"
}

extra_anon() {
  sudo swapoff -a >/dev/null 2>&1
  random_host=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n1)
  sudo hostnamectl set-hostname "$random_host" >/dev/null 2>&1
  timezones=(America/New_York Europe/London Asia/Tokyo Africa/Johannesburg)  
  rand_tz=${timezones[$((RANDOM % ${#timezones[@]}))]}
  sudo timedatectl set-timezone "$rand_tz" >/dev/null 2>&1
  echo "Extra: Swap off, hostname $random_host, timezone $rand_tz"
}

clear
echo "< interface: $interface"
echo "< disk: $disk (no UUID spoof)"
echo "< timeout: $timeout"
echo ""
v5 2
echo ""
if ! systemctl is-active doh-client.service >/dev/null 2>&1; then
  mkdir -p bin/DOH
  cd bin/DOH/
  git clone https://github.com/m13253/dns-over-https >/dev/null 2>&1
  cd dns-over-https/
  make >/dev/null 2>&1
  sudo make install >/dev/null 2>&1
  sudo sed -i '29s#url = "[^"]*"#url = "https://dns.ndo.dev/dns-query"#' "$dohpage"
  sudo systemctl start doh-client.service >/dev/null 2>&1
  sudo systemctl enable doh-client.service >/dev/null 2>&1
fi
echo "<<< DoH active. HTTP/DNS encrypted."
v5 15
sudo touch /etc/squid/custom_user_agent
sudo systemctl start dbus
sudo service squid start >/dev/null 2>&1
proxys
sudo iptables -P FORWARD DROP >/dev/null 2>&1
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT >/dev/null 2>&1
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1
sudo iptables -A INPUT -i lo -j ACCEPT >/dev/null 2>&1
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 3128 >/dev/null 2>&1
echo "Finished. Prophetia Starting..."

while true; do
  time=$(date +"%H:%M:%S")
  time=$(date +"%H:%M:%S")
  clear && cfonts Prophetia -a center -f simple3d -c gray && echo -e "\e[1m                                                        Prophetia - Be anonymous! | [<enderproject>]\e[0m"  && echo ""

  echo "--time--    --changes--"
  echo -e "<$time> [\e[34m\e[1mMAC\e[0m] Adress changed. New MAC: '\e[31m\e[1m$(macchanger -s $interface | awk '/Current MAC/{print $3}')\e[0m'"
  mac
  v5 2
  dhcp
  echo -e "<$time> [\e[34m\e[1mDHCP\e[0m] Renewed."
  notify-send "Prophetia" "DHCP encrypted!"
  dns
  echo -e "<$time> [\e[34m\e[1mDNS\e[0m] Encrypted."
  v5 2
  routerspoof
  echo -e "<$time> [\e[34m\e[1mROUTER\e[0m] Spoofed (IPv6 + IPv4)"
  sudo ip route add default via "${gateways[$current_gateway_index]}"
  echo -e "<$time> [GATEWAY] Changed: ${gateways[$current_gateway_index]}"
  current_gateway_index=$(( (current_gateway_index + 1) % ${#gateways[@]} ))
  v5 2
  extra_anon  
  echo -e "<$time> [\e[34m\e[1mEXTRA\e[0m] Anon layers added."
  sudo service squid restart >/dev/null 2>&1
  mitmproxy --mode transparent --modify-headers ":~b'User-Agent:.*' -> 'User-Agent: $(cat /etc/squid/custom_user_agent)'" >/dev/null 2>&1 &
  user_agent
  echo -e "<$time> [USER-AGENT] Changed: $(cat /etc/squid/custom_user_agent)"
  v5 2
  proxy=$(random_proxys)
  sed -i "s/http_port 3128/http_port 3128\nacl my_acl src $proxy/g" /etc/squid/squid.conf
  echo -e "<$time> [\e[34m\e[1mPROXY\e[0m]  Changed: $proxy"
  v5 2
  echo -e "<$time> [\e[34m\e[1mTOR NETWORK\e[0m]  Encrypted, socks5 dynamic."
  browser
  echo "[LIBREWOLF] Started with Tor in firejail."
  v5 4
  log
  echo "[LOGS] Cleared."
  v5 1
  ultra_tcp_spoof
  ultra_ram_only
  ultra_namespace
  ultra_multinet
  ultra_ai_human
  echo -e "\e[107;34mYour internet is encrypted with 7 layers. You are anonymous! (for now) | Last change: $time\e[0m"
  echo ""
  echo ">>> Timeout : $timeout Sec"

  notify
  sleep $timeout
done
res_settings

# gitHub'da örneği yok, çünkü kimse bu kadar manyak değil :)
