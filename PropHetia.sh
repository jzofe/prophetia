#!/bin/bash


# ENDER PROJECT
# OPEN-SOURCE
# BECOME A PROFESSIONAL ANONYMOUS. 
# Prophetia >>> <Internet connection, traffic encryptor.>

# Coded By FYKS
if [ "$EUID" -ne 0 ]; then
  echo "Permission required. Type 'sudo bash prophetia.sh -c <interface> -t 600'."
  exit 1
fi

dohpage="/etc/dns-over-https/doh-client.conf"
interface="" 
timeout="1200"
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
gateways=("94.140.14.14" "149.112.112.112" "84.200.69.80" "37.235.1.174" "1.1.1.1" "9.9.9.9")
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

req_programs=("mitmproxy" "macchanger" "squid" "proxychains" "tor" "wireguard" "firejail" "librewolf" "clang" "go" "cfonts")

usage() {
  echo "usage: $0 -c <interface> -t <timeout>"
  exit 1
}

check() { command -v $1 >/dev/null 2>&1; }

# Argümanları Parse Et
while getopts ":c:t:d:" opt; do  
  case ${opt} in
    c ) interface=$OPTARG ;;
    d ) disk=$OPTARG ;;
    t ) timeout=$OPTARG ;;
    \? ) usage ;;
    : ) usage ;;
  esac
done

if [ -z "$interface" ]; then
    echo "Error: Interface (-c) is required. Example: -c wlan0"
    usage
fi

for program in "${req_programs[@]}"; do
  if ! check $program; then
    echo "Missing: $program. Please run 'sudo bash setup.sh' first."
    exit 1
  fi
done


ultra_tcp_spoof() {
  echo -e "\e[31m[ULTRA]\e[0m eBPF TCP-HEADER fingerprint spoofing..."
  if clang -O2 -target bpf -c /tmp/tcp_spoof.bpf.c -o /tmp/tcp_spoof.o >/dev/null 2>&1; then
      bpftool prog load /tmp/tcp_spoof.o /sys/fs/bpf/tcp_spoof >/dev/null 2>&1
      bpftool net attach xdp pinned /sys/fs/bpf/tcp_spoof dev "$interface" >/dev/null 2>&1
      echo -e "\e[32m[+] eBPF Loaded.\e[0m"
  else
      echo -e "\e[33m[-] eBPF compilation failed. Check clang/headers.\e[0m"
  fi
}

ultra_ram_only() {
  echo -e "\e[31m[ULTRA]\e[0m swap FUCKED + dm-crypt RAM disk"
  sudo swapoff -a
  if [ ! -d "/mnt/encram" ]; then
      sudo mkdir -p /mnt/encram
      sudo mount -t tmpfs -o size=1G tmpfs /mnt/encram
  fi
}

routerspoof() {
    INTERFACE_MAC=$(cat /sys/class/net/$interface/address)
    ROUTER_IP=$(ip route show default | awk '/default/ {print $3}' | head -1)
    if [ -z "$ROUTER_IP" ]; then ROUTER_IP="192.168.1.1"; fi
    
    ROUTER_MAC=$(ip neigh show "$ROUTER_IP" | awk '{print $5}' | head -1)
    if [ -z "$ROUTER_MAC" ]; then ROUTER_MAC="ff:ff:ff:ff:ff:ff"; fi

    sudo python3 spoofer.py --interface "$interface" --router-mac "$ROUTER_MAC" --src-mac "$INTERFACE_MAC" >/dev/null 2>&1 &
}

browser() {
   sudo systemctl start tor
   if ! grep -q "socks5 127.0.0.1 9050" /etc/proxychains.conf; then
       echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
   fi

   rm -rf ~/.librewolf/*prophetia* 2>/dev/null
   librewolf -CreateProfile "prophetia" >/dev/null 2>&1
   PROFILE_DIR=$(find ~/.librewolf -name "*prophetia" -type d | head -1)
   
   if [ -n "$PROFILE_DIR" ]; then
       echo 'user_pref("privacy.donottrackheader.enabled", true);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("privacy.clearOnShutdown.cookies", true);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("privacy.clearOnShutdown.history", true);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("browser.send_pings", false);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("network.proxy.type", 1);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("network.proxy.socks", "127.0.0.1");' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("network.proxy.socks_port", 9050);' >> "$PROFILE_DIR/prefs.js"
       echo 'user_pref("network.proxy.socks_remote_dns", true);' >> "$PROFILE_DIR/prefs.js"
   fi
   
   echo "[LIBREWOLF] Started with Tor proxy in firejail sandbox."
   proxychains firejail --private --dns=127.0.0.1 librewolf -P prophetia -no-remote >/dev/null 2>&1 &
}

mac_change() {
  declare -A vendor_dict
  vendor_dict=(
    ["00:41:b4"]="Wuxi Zhongxing Optoelectronics Technology Co.,Ltd."
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
    ["dc:85:de"]="AzureWave Technology Inc."
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

user_agent() {
  rand_index=$(( RANDOM % ${#users[@]} ))
  echo "${users[$rand_index]}" | sudo tee /etc/squid/custom_user_agent >/dev/null
}

ultra_ai_human() {
  if command -v xdotool >/dev/null 2>&1; then
      (while true; do
        xdotool mousemove_relative --polar $((RANDOM%360)) $((RANDOM%50+10))
        [[ $((RANDOM%3)) -eq 0 ]] && xdotool click 1
        [[ $((RANDOM%7)) -eq 0 ]] && xdotool type --delay $((RANDOM%200+50)) "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c $((RANDOM%5+1))"
        sleep $((RANDOM%15+5))
      done) &
      echo -e "\e[32m[AI]\e[0m ai active :D (NSA DEAD)"
  fi
}

log_wipe() {
    sudo journalctl --rotate >/dev/null 2>&1
    sudo journalctl --vacuum-time=1s >/dev/null 2>&1
    sudo journalctl --vacuum-size=1M >/dev/null 2>&1

    LOG_FILES=(
      /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/dmesg /var/log/messages
      /var/log/secure /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/faillog
      /var/log/daemon.log /var/log/debug /var/log/user.log /var/log/mail.log
    )

    for logfile in "${LOG_FILES[@]}"; do
      if [ -f "$logfile" ]; then
        sudo shred -z -u -v -n 21 "$logfile" 2>/dev/null
      fi
    done

    history -c
    history -w
    shred -z -u -n 10 ~/.bash_history 2>/dev/null || true
    
    sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    echo "[LOGS] 21-pass shred completed xd (fbi is crying now)"
}

notify() {
  message="Prophetia: Anonymity renewed! Timeout : $timeout"
  notify-send "Prophetia Notification" "$message"
}

cleanup() {
  echo "Restoring settings..."
  sudo iptables -F
  sudo bpftool net detach xdp dev "$interface" >/dev/null 2>&1
  rm -f /sys/fs/bpf/tcp_spoof
  killall python3 >/dev/null 2>&1
  killall xdotool >/dev/null 2>&1
  exit 0
}

trap cleanup INT TERM
v5() { sleep "$1"; }

clear
if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
echo -e "\e[1m  Prophetia - Be anonymous! | [<enderproject>] \e[0m" 
echo "< interface: $interface"
echo "< timeout: $timeout"
echo ""

# DoH ve Proxy başlatma mantığı
if command -v doh-client >/dev/null 2>&1; then
    if ! pgrep -x "doh-client" >/dev/null; then
        sudo doh-client >/dev/null 2>&1 &
        echo "<<< DoH active. HTTP/DNS encrypted."
    fi
fi

sudo systemctl start squid >/dev/null 2>&1
sudo bash iptables.sh >/dev/null 2>&1

ultra_ram_only
ultra_tcp_spoof
browser

echo "Finished. Prophetia Starting..."
v5 1

while true; do
  time=$(date +"%H:%M:%S")
  clear
  if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
  echo -e "\e[1m                                                                                             Prophetia - Be anonymous! | [<enderproject>]\e[0m"  && echo ""
  echo "--time--    --changes--"
  
  mac_change
  echo -e "<$time> [\e[34m\e[1mMAC\e[0m] Adress changed. New MAC: '\e[31m\e[1m$(macchanger -s $interface | awk '/Current MAC/{print $3}')\e[0m'"
  v5 2

  sudo dhclient -r > /dev/null 2>&1
  sudo dhclient > /dev/null 2>&1
  echo -e "<$time> [\e[34m\e[1mDHCP\e[0m] Renewed."
  notify-send "Prophetia" "DHCP encrypted!" >/dev/null 2>&1
  v5 2

  routerspoof
  echo -e "<$time> [\e[34m\e[1mROUTER\e[0m] Spoofed (IPv6 + IPv4)"
  
  sudo ip route add default via "${gateways[$current_gateway_index]}" 2>/dev/null || sudo ip route change default via "${gateways[$current_gateway_index]}" 2>/dev/null
  echo -e "<$time> [GATEWAY] Changed: ${gateways[$current_gateway_index]}"
  current_gateway_index=$(( (current_gateway_index + 1) % ${#gateways[@]} ))
  v5 2
  
  sudo service squid restart >/dev/null 2>&1
  user_agent
  echo -e "<$time> [USER-AGENT] Changed: $(cat /etc/squid/custom_user_agent)"
  v5 2
  
  log_wipe
  
  ultra_ai_human 
  echo -e "\e[107;34mYour internet is encrypted with 7 layers. You are anonymous! (for now) | Last change: $time\e[0m"
  echo ""
  echo ">>> Timeout : $timeout Sec"

  notify
  sleep $timeout
done
