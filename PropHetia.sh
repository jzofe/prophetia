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

NETNS_NAME="prophetia_netns"
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

users=(
    "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 11; SM-A405FN Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.166 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 10; RMX1851 Build/QKQ1.190918.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.83 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 7.1.1; ZC520KL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.96 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36" 
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36" 
    "Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0"
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36" 
    "Mozilla/5.0 (Linux; U; Android 10; tr-tr; Redmi Note 7 Build/QKQ1.190910.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/71.0.3578.141 Mobile Safari/537.36 XiaoMi/MiuiBrowser/12.5.2-gn"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36/DiUzeNty-1"
)

req_programs=("mitmproxy" "macchanger" "squid" "proxychains" "tor" "wireguard" "firejail" "librewolf" "clang" "go" "cfonts" "git" "python3")

usage() {
  echo "usage: $0 -c <interface> -t <timeout>"
  exit 1
}
traff_noiser() {
    echo -e ">>> [\e[35mNOISER\e[0m] Checking Traffic Noiser repository..."
    
    if [ ! -d "$NOISY_DIR" ]; then
        mkdir -p "$PWD/bin"
        if git clone https://github.com/1tayH/noisy "$NOISY_DIR" >/dev/null 2>&1; then
            echo -e ">>> [\e[32m+\e[0m] Noiser cloned successfully."
        else
            echo -e ">>> [\e[31m!\e[0m] Git clone failed."
        fi
    else
        echo -e "ok"
    fi
}
start_noiser() {
    if [ -f "$NOISY_DIR/noisy.py" ]; then
        ip netns exec "$NETNS_NAME" sudo python3 "$NOISY_DIR/noisy.py" --config "$NOISY_DIR/config.json" >/dev/null 2>&1 &
        echo -e "<$time> [\e[35mNOISER\e[0m] Started noise generation in Netns."
    else
        echo -e "<$time> [\e[31m!\e[0m] Noisy failed."
    fi
}

check() { command -v $1 >/dev/null 2>&1; }

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
    
    ip->ttl = 64 + (bpf_get_prandom_u32() % 60);
    tcp->window = htons(10000 + (bpf_get_prandom_u32() % 50000));
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
EOF

  if clang -O2 -target bpf -c /tmp/tcp_spoof.bpf.c -o /tmp/tcp_spoof.o >/dev/null 2>&1; then
      bpftool prog load /tmp/tcp_spoof.o /sys/fs/bpf/tcp_spoof >/dev/null 2>&1
      bpftool net attach xdp pinned /sys/fs/bpf/tcp_spoof dev "$interface" >/dev/null 2>&1
      echo -e "<$time> \e[32m[eBPF] eBPF Loaded.\e[0m"
  else
      echo -e "\e[33m[-] eBPF compilation failed. Check clang/headers.${NC}"
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
    INTERFACE_MAC=$(ip netns exec "$NETNS_NAME" cat /sys/class/net/$interface/address)
    ROUTER_IP=$(ip netns exec "$NETNS_NAME" ip route show default | awk '/default/ {print $3}' | head -1)
    if [ -z "$ROUTER_IP" ]; then ROUTER_IP="192.168.1.1"; fi
    
    ROUTER_MAC=$(ip netns exec "$NETNS_NAME" ip neigh show "$ROUTER_IP" | awk '{print $5}' | head -1)
    if [ -z "$ROUTER_MAC" ]; then ROUTER_MAC="ff:ff:ff:ff:ff:ff"; fi

    ip netns exec "$NETNS_NAME" sudo python3 spoofer.py --interface "$interface" --router-mac "$ROUTER_MAC" --src-mac "$INTERFACE_MAC" >/dev/null 2>&1 &
}

browser() {
    ip netns exec "$NETNS_NAME" sudo systemctl start tor
    
    if ! ip netns exec "$NETNS_NAME" grep -q "socks5 127.0.0.1 9050" /etc/proxychains.conf; then
        ip netns exec "$NETNS_NAME" echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
    fi
    
    echo "[LIBREWOLF] Started with Tor proxy in firejail sandbox (Inside $NETNS_NAME)."
    ip netns exec "$NETNS_NAME" proxychains firejail --private --dns=127.0.0.1 librewolf -P prophetia -no-remote >/dev/null 2>&1 &
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
mtu_jitter() {
    RANDOM_MTU=$(( RANDOM % 101 + 1400 )) 
    ip netns exec "$NETNS_NAME" sudo ip link set dev "$interface" mtu "$RANDOM_MTU" >/dev/null 2>&1
    echo -e "<$time> [\e[34mMTU\e[0m] Changed to $RANDOM_MTU (Inside Netns)."
}

ultra_sysctl_harden() {
    echo -e "<$time> [\e[33mKERNEL\e[0m] Applying Sysctl Hardening..."
    
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
    
    echo -e "<$time> [\e[33mKERNEL\e[0m] Sysctl hardened (ICMP, Timestamps Disabled)."
}

user_agent() {
  rand_index=$(( RANDOM % ${#users[@]} ))
  echo "${users[$rand_index]}" | ip netns exec "$NETNS_NAME" sudo tee /etc/squid/custom_user_agent >/dev/null
}
log_spoof() {
    echo -e "<$time> [\e[33mLOG\e[0m] Generating realistic, dense fake logs..."

    history -c
    
    FAKE_COMMANDS=(
        "sudo apt update && sudo apt upgrade -y"
        "nano /etc/ssh/sshd_config"
        "python3 deploy_script.py --env=staging"
        "ping 10.0.0.1 -c 5"
        "git pull origin main"
        "docker ps -a"
        "cd /var/www/html"
        "vim .env"
        "grep -r 'TODO' ."
        "ip a"
        "systemctl status nginx"
    )
    
    for i in $(seq 1 $((RANDOM % 15 + 10))); do
        TIMESTAMP=$(date +%s -d "$((i-10)) days ago")
        COMMAND="${FAKE_COMMANDS[$RANDOM % ${#FAKE_COMMANDS[@]}]}"
        echo "#$TIMESTAMP" >> ~/.bash_history
        echo "$COMMAND" >> ~/.bash_history
    done
    
    history -w 

    LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/kern.log")
    
    truncate -s 0 /var/log/wtmp 2>/dev/null
    truncate -s 0 /var/log/btmp 2>/dev/null

    for logfile in "${LOG_FILES[@]}"; do
        if [ -f "$logfile" ]; then
            sudo shred -z -u -n 5 "$logfile" 2>/dev/null

            FAKE_LINES=""
            for j in $(seq 1 $((RANDOM % 50 + 10))); do 
                FAKE_DATE=$(date -d "$((RANDOM % 7)) days ago" "+%b %d %H:%M:%S")
                
                case $((RANDOM % 4)) in
                    0) LINE="host systemd[1]: Starting Session $j of user randomuser." ;;
                    1) LINE="host kernel: [  2.000000] usb 1-1: new high-speed USB device number $j using xhci_hcd" ;;
                    2) LINE="host sshd[999$j]: Accepted password for randomuser from 192.168.1.10 port 5$j ssh2" ;;
                    3) LINE="host CRON[1$j]: (randomuser) CMD (/usr/bin/some-maintenance-script)" ;;
                esac
                FAKE_LINES="$FAKE_LINES\n$FAKE_DATE $LINE"
            done
            echo -e "$FAKE_LINES" | sudo tee "$logfile" >/dev/null
            sudo logrotate -f /etc/logrotate.conf 2>/dev/null || true
            echo -e "    [Log: $logfile] Faked and rotated."
        fi
    done
    
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    
    echo "[LOGS] Sophisticated log spoofing complete. System appears normal."
}
ultra_ai_human() {
  if command -v xdotool >/dev/null 2>&1; then
      (while true; do
        xdotool mousemove_relative --polar $((RANDOM%360)) $((RANDOM%50+10))
        [[ $((RANDOM%3)) -eq 0 ]] && xdotool click 1
        [[ $((RANDOM%7)) -eq 0 ]] && xdotool type --delay $((RANDOM%200+50)) "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c $((RANDOM%5+1))"
        sleep $((RANDOM%15+5))
      done) &
      echo -e "<$time> \e[32m[AI]\e[0m ai active :D (NSA DEAD)"
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

clock_jitter() {
    JITTER_MS=$(( (RANDOM % 101) - 50 ))
    ip netns exec "$NETNS_NAME" sudo date +%T.%N -s "$(date +%T.%N -d "now + $JITTER_MS milliseconds")" >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sudo systemctl stop systemd-timesyncd 2>/dev/null || true
    echo -e "<$time> [\e[35mCLOCK\e[0m] Time Jittered by $JITTER_MS ms (Inside Netns)."
}

create_netns() {
  echo -e "<$time> [\e[36mNETNS\e[0m] Creating isolated namespace: $NETNS_NAME"

  ip netns add "$NETNS_NAME"
  ip link set dev "$interface" netns "$NETNS_NAME"
  ip netns exec "$NETNS_NAME" ip link set dev lo up
  ip netns exec "$NETNS_NAME" ip link set dev "$interface" up
  
  ip netns exec "$NETNS_NAME" sudo dhclient -r "$interface" > /dev/null 2>&1
  ip netns exec "$NETNS_NAME" sudo dhclient "$interface" > /dev/null 2>&1
  
  echo -e ">>> [\e[36mNETNS\e[0m] Interface '$interface' isolated and configured."
}

destroy_netns() {
  if ip netns pids "$NETNS_NAME" >/dev/null 2>&1; then
      echo -e ">>> [\e[36mNETNS\e[0m] Destroying Namespace: $NETNS_NAME"
      ip netns exec "$NETNS_NAME" ip link set dev "$interface" netns 1 2>/dev/null
      ip netns pids "$NETNS_NAME" | xargs kill -9 2>/dev/null
      ip netns delete "$NETNS_NAME"
      sudo ifconfig "$interface" up 2>/dev/null
  fi
}

notify() {
  message="Prophetia: Anonymity renewed! Timeout : $timeout"
  ip netns exec "$NETNS_NAME" notify-send "Prophetia Notification" "$message" 2>/dev/null || true
}

cleanup() {
  echo "Restoring settings..."
  sudo iptables -F
  sudo bpftool net detach xdp dev "$interface" >/dev/null 2>&1
  rm -f /sys/fs/bpf/tcp_spoof
  killall python3 >/dev/null 2>&1
  killall xdotool >/dev/null 2>&1
  
  destroy_netns 
  exit 0
}

trap cleanup INT TERM
v5() { sleep "$1"; }
clear
if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
echo -e "\e[1m  Prophetia - Network Namespace Spoofer | [<enderproject>] \e[0m" 

sudo systemctl start squid >/dev/null 2>&1
sudo bash iptables.sh >/dev/null 2>&1

ultra_ram_only
ultra_tcp_spoof 
ultra_ai_human 
traff_noiser

echo "Finished Initial Setup. Prophetia Starting Loop..."
v5 1

while true; do
  time=$(date +"%H:%M:%S")
  clear
  if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
  echo -e "\e[1m                                                                                             Prophetia - Be anonymous! | [<enderproject>]\e[0m"  && echo ""
  echo "--time--    --changes--"
  destroy_netns
  mac_change
  echo -e "<$time> [\e[34m\e[1mMAC\e[0m] Adress changed. New MAC: '\e[31m\e[1m$(macchanger -s $interface | awk '/Current MAC/{print $3}')\e[0m'"
  v5 1
  create_netns
  v5 1
  ultra_sysctl_harden 
  mtu_jitter
  clock_jitter
  ip netns exec "$NETNS_NAME" sudo doh-client >/dev/null 2>&1 &
  ip netns exec "$NETNS_NAME" sudo systemctl start tor >/dev/null 2>&1
  ip netns exec "$NETNS_NAME" sudo service squid restart >/dev/null 2>&1
  
  routerspoof
  echo -e "<$time> [\e[34m\e[1mROUTER\e[0m] Spoofed (IPv6 + IPv4) IN NETNS"
  
  ip netns exec "$NETNS_NAME" sudo ip route add default via "${gateways[$current_gateway_index]}" 2>/dev/null || ip netns exec "$NETNS_NAME" sudo ip route change default via "${gateways[$current_gateway_index]}" 2>/dev/null
  echo -e "<$time> [\e[34m\e[1mGATEWAY\e[0m]Changed: ${gateways[$current_gateway_index]} (Isolated)"
  current_gateway_index=$(( (current_gateway_index + 1) % ${#gateways[@]} ))
  v5 2
  
  user_agent
  echo -e "<$time> [USER-AGENT] Changed: $(ip netns exec "$NETNS_NAME" cat /etc/squid/custom_user_agent | head -n 1)"
  v5 2
  start_noiser
  if ! pgrep -f "librewolf -P prophetia" >/dev/null; then
     browser
  fi
  
  log_wipe
  log_spoof
  echo -e "\e[107;34mYour internet is encrypted with 15 layers. You are anonymous! (for now) | Last change: $time\e[0m"
  echo ""
  echo ">>> Isolated in Netns: $NETNS_NAME | Timeout : $timeout Sec"

  notify
  sleep $timeout
done
