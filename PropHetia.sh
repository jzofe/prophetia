#!/bin/bash
# ENDER PROJECT - ULTIMATE FIXED VERSION

# OPEN-SOURCE
# BECOME A PROFESSIONAL ANONYMOUS.
# Prophetia >>> <Internet connection, traffic encryptor.>

# Coded By FYKS 

NETNS_NAME="prophetia_netns"
interface=""
timeout="3600"
NOISY_DIR="$PWD/noisy"
RAMDISK_PATH="/mnt/encram"
TOR_DATA_DIR="$RAMDISK_PATH/tor_data"
SQUID_CACHE_DIR="$RAMDISK_PATH/squid_cache"
TOR_PID_FILE="$TOR_DATA_DIR/tor.pid"
SQUID_PID_FILE="$SQUID_CACHE_DIR/squid.pid"

gateways=("94.140.14.14" "149.112.112.112" "84.200.69.80" "37.235.1.174" "84.200.70.40")
current_gateway_index=0

users=(
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.10 Safari/605.1.15"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/360.1.737798518 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
)

req_programs=("mitmproxy" "macchanger" "squid" "proxychains" "tor" "wireguard" "firejail" "librewolf" "go" "cfonts" "git" "python3" "clang" "bpftool" "cryptsetup")

usage() {
    echo "usage: $0 -c <interface> -t <timeout>"
    exit 1
}

traff_noiser() {
    if [ ! -d "$NOISY_DIR" ]; then
        mkdir -p "$PWD/bin"
        git clone https://github.com/1tayH/noisy "$NOISY_DIR" >/dev/null 2>&1
    fi
}

start_noiser() {
    if [ -f "$NOISY_DIR/noisy.py" ]; then
        ip netns exec "$NETNS_NAME" python3 "$NOISY_DIR/noisy.py" --config "$NOISY_DIR/config.json" >/dev/null 2>&1 &
    fi
}

check() { command -v $1 >/dev/null 2>&1; }

while getopts ":c:t:" opt; do
    case ${opt} in
        c ) interface=$OPTARG ;;
        t ) timeout=$OPTARG ;;
        \? ) usage ;;
        : ) usage ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo "Permission required. Type 'sudo bash $0 -c <interface> -t 3600'."
    exit 1
fi

if [ -z "$interface" ]; then
    echo "Error: Interface (-c) is required. Example: -c wlan0"
    usage
fi

for program in "${req_programs[@]}"; do
    if ! check $program; then
        echo "Missing: $program. Please install first."
        exit 1
    fi
done

ultra_tcp_spoof() {
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
    
    ip->ttl = 64;  
    tcp->window = htons(65535); 
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
EOF
    if clang -O2 -target bpf -c /tmp/tcp_spoof.bpf.c -o /tmp/tcp_spoof.o >/dev/null 2>&1; then
        mkdir -p /sys/fs/bpf
        bpftool prog load /tmp/tcp_spoof.o /sys/fs/bpf/tcp_spoof >/dev/null 2>&1
        bpftool net attach xdp pinned /sys/fs/bpf/tcp_spoof dev "$interface" >/dev/null 2>&1
    fi
}

ultra_ram_only() {
    swapoff -a
    if ! mountpoint -q "$RAMDISK_PATH"; then
        modprobe brd rd_nr=1 rd_size=1048576 2>/dev/null
        mkdir -p "$RAMDISK_PATH"
        if ! [ -b "/dev/mapper/encram" ]; then
            cryptsetup luksFormat /dev/ram0 --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --batch-mode --key-file /dev/urandom >/dev/null 2>&1
            cryptsetup open /dev/ram0 encram >/dev/null 2>&1
            mkfs.ext4 -F /dev/mapper/encram >/dev/null 2>&1
        fi
        mount /dev/mapper/encram "$RAMDISK_PATH"
        mkdir -p "$TOR_DATA_DIR" "$SQUID_CACHE_DIR"
        chmod -R 700 "$TOR_DATA_DIR" "$SQUID_CACHE_DIR"
        chown -R proxy:proxy "$SQUID_CACHE_DIR" 2>/dev/null
    fi
}

browser() {
    cat << EOF > /tmp/proxychains_prophetia.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050
EOF
    ip netns exec "$NETNS_NAME" rm -rf ~/.librewolf/prophetia 2>/dev/null
    ip netns exec "$NETNS_NAME" proxychains -f /tmp/proxychains_prophetia.conf firejail --private --dns=127.0.0.1 librewolf -P prophetia -no-remote >/dev/null 2>&1 &
}

mac_change() {
    declare -A vendor_dict
    vendor_dict=(
        ["00:1C:B3"]="Apple Inc."
        ["00:25:00"]="Intel Corporate"
        ["F0:9F:C2"]="Samsung Electronics Co.,Ltd"
        ["D8:BB:2C"]="Google, Inc."
    )
    prefix_list=("${!vendor_dict[@]}")
    random_index=$((RANDOM % ${#prefix_list[@]}))
    selected_prefix=${prefix_list[$random_index]}
    random_mac=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    full_mac_address="${selected_prefix,,}:$random_mac"
    
    ifconfig $interface down > /dev/null 2>&1
    macchanger -m $full_mac_address $interface > /dev/null 2>&1
    ifconfig $interface up > /dev/null 2>&1
}

ultra_sysctl_harden() {
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
}

user_agent() {
    rand_index=$(( RANDOM % ${#users[@]} ))
    echo "${users[$rand_index]}" | ip netns exec "$NETNS_NAME" tee /etc/squid/custom_user_agent >/dev/null
}
clock_jitter() {
    JITTER_MS=$(( (RANDOM % 101) - 50 ))
    ip netns exec "$NETNS_NAME" sudo date +%T.%N -s "$(date +%T.%N -d "now + $JITTER_MS milliseconds")" >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" sudo systemctl stop systemd-timesyncd 2>/dev/null || true
    echo -e "<$time> [\e[35mCLOCK\e[0m] Time Jittered by $JITTER_MS ms (Inside Netns)."
}
log_spoof() {
    history -c
    FAKE_COMMANDS=(
        "sudo apt update && sudo apt upgrade -y"
        "nano /etc/ssh/sshd_config"
        "python3 deploy_script.py --env=staging"
        "ping 10.0.0.1 -c 5"
        "git pull origin main"
        "docker ps -a"
        "systemctl status nginx"
    )
    for i in $(seq 1 $((RANDOM % 15 + 10))); do
        TIMESTAMP=$(date +%s -d "$((i-10)) days ago")
        COMMAND="${FAKE_COMMANDS[$RANDOM % ${#FAKE_COMMANDS[@]}]}"
        echo "#$TIMESTAMP" >> ~/.bash_history
        echo "$COMMAND" >> ~/.bash_history
    done
    history -w
    LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/kern.log" "/var/log/alternatives.log" "/var/log/dpkg.log")
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
                    1) LINE="host kernel: [ 2.000000] usb 1-1: new high-speed USB device number $j using xhci_hcd" ;;
                    2) LINE="host sshd[999$j]: Accepted password for randomuser from 192.168.1.10 port 5$j ssh2" ;;
                    3) LINE="host CRON[1$j]: (randomuser) CMD (/usr/bin/some-maintenance-script)" ;;
                esac
                FAKE_LINES="$FAKE_LINES\n$FAKE_DATE $LINE"
            done
            echo -e "$FAKE_LINES" | sudo tee "$logfile" >/dev/null
            sudo logrotate -f /etc/logrotate.conf 2>/dev/null || true
        fi
    done
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
}

ultra_ai_human() {
    if command -v xdotool >/dev/null 2>&1; then
        (while true; do
            xdotool mousemove_relative --polar $((RANDOM%360)) $((RANDOM%20+5))
            sleep $((RANDOM%30+10))
        done) &
    fi
}

log_wipe() {
    journalctl --rotate >/dev/null 2>&1
    journalctl --vacuum-time=1s >/dev/null 2>&1
    LOG_FILES=("/var/log/syslog" "/var/log/auth.log")
    for logfile in "${LOG_FILES[@]}"; do
        if [ -f "$logfile" ]; then
            shred -z -u -n 3 "$logfile" 2>/dev/null
        fi
    done
    history -c
    history -w
    sync && echo 3 > /proc/sys/vm/drop_caches >/dev/null
}

create_netns() {
    ip netns add "$NETNS_NAME" 2>/dev/null
    ip link set dev "$interface" netns "$NETNS_NAME"
    ip netns exec "$NETNS_NAME" ip link set dev lo up
    ip netns exec "$NETNS_NAME" ip link set dev "$interface" up
    ip netns exec "$NETNS_NAME" dhclient -r "$interface" > /dev/null 2>&1
    ip netns exec "$NETNS_NAME" dhclient "$interface" > /dev/null 2>&1
}

destroy_netns() {
    if ip netns pids "$NETNS_NAME" >/dev/null 2>&1; then
        kill -SIGTERM "$(cat "$TOR_PID_FILE")" 2>/dev/null
        kill -SIGTERM "$(cat "$SQUID_PID_FILE")" 2>/dev/null
        ip netns pids "$NETNS_NAME" | xargs kill -9 2>/dev/null
        ip netns exec "$NETNS_NAME" ip link set dev "$interface" netns 1 2>/dev/null
        ip netns delete "$NETNS_NAME" 2>/dev/null
        ifconfig "$interface" up 2>/dev/null
    fi
}

cleanup_ramdisk() {
    if mountpoint -q "$RAMDISK_PATH"; then
        umount "$RAMDISK_PATH" 2>/dev/null
    fi
    if [ -b "/dev/mapper/encram" ]; then
        cryptsetup close encram 2>/dev/null
    fi
    rmmod brd 2>/dev/null
    swapoff -a
}

notify() {
    message="Prophetia: Renewed! Timeout ~$(($timeout / 60)) Minutes"
    ip netns exec "$NETNS_NAME" notify-send "Prophetia" "$message" 2>/dev/null || true
}

cleanup() {
    killall python3 >/dev/null 2>&1
    killall xdotool >/dev/null 2>&1
    killall tor >/dev/null 2>&1
    killall squid >/dev/null 2>&1
    killall doh-client >/dev/null 2>&1
    
    destroy_netns 
    
    cleanup_ramdisk

    iptables -F
    bpftool net detach xdp dev "$interface" >/dev/null 2>&1
    rm -f /sys/fs/bpf/tcp_spoof
    exit 0
}

start_tor_squid() {
    local TOR_CONF_FILE="/tmp/torrc_prophetia"
    local SQUID_CONF_FILE="/tmp/squid.conf"

    cat << EOF > "$TOR_CONF_FILE"
DataDirectory $TOR_DATA_DIR
PidFile $TOR_PID_FILE
SocksPort 9050
RunAsDaemon 1
EOF

    cat << EOF > "$SQUID_CONF_FILE"
http_port 3128
refresh_pattern . 0 20% 43200
cache_dir ufs $SQUID_CACHE_DIR 100 16 256
access_log none
cache_log none
coredump_dir /dev/null
forwarded_for off
via off
request_header_access From deny all
request_header_access Via deny all
request_header_access Cache-Control deny all
request_header_access Referer deny all
request_header_access X-Forwarded-For deny all
request_header_access User-Agent deny all
request_header_replace User-Agent "$(ip netns exec "$NETNS_NAME" cat /etc/squid/custom_user_agent)"
cache deny all
never_direct allow all
pipeline_prefetch disable
EOF

    ip netns exec "$NETNS_NAME" tor -f "$TOR_CONF_FILE" >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" squid -N -f "$SQUID_CONF_FILE" -z >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" squid -N -f "$SQUID_CONF_FILE" -k shutdown >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" squid -N -f "$SQUID_CONF_FILE" -D -p "$SQUID_PID_FILE" >/dev/null 2>&1

    
    local TIMEOUT=30
    local COUNT=0
    while [ ! -f "$TOR_PID_FILE" ] || [ ! -f "$SQUID_PID_FILE" ] && [ $COUNT -lt $TIMEOUT ]; do
        sleep 1
        COUNT=$((COUNT + 1))
    done
}

trap cleanup INT TERM
v5() { sleep "$1"; }
clear
if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
echo -e "\e[1m  Prophetia - Network Spoofer | [<enderproject>] \e[0m" 

iptables_setup() {
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X

    sudo iptables -I INPUT -m ttl --ttl-lt 11 -j DROP 2>/dev/null
    sudo ip6tables -A INPUT -m hl --hl-lt 11 -j DROP 2>/dev/null

    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
}

iptables_setup
ultra_ram_only
ultra_tcp_spoof
ultra_ai_human 
traff_noiser
clock_jitter
v5 1

mac_loop_counter=0

while true; do
    time=$(date +"%H:%M:%S")
    clear
    if command -v cfonts >/dev/null 2>&1; then cfonts Prophetia -a center -f simple3d -c gray; else echo "PROPHETIA"; fi
    echo -e "\e[1m                                                                                                                   Prophetia - Be anonymous! | [<enderproject>]\e[0m"  && echo ""
    echo "--time--      --changes--"
    
    if [ $mac_loop_counter -eq 0 ]; then
        destroy_netns
        mac_change
        echo -e "<$time> [\e[34mMAC\e[0m] Changed: $(macchanger -s $interface | awk '/Current MAC/{print $3}')"
        create_netns
        
        ip netns exec "$NETNS_NAME" ip route add default via "${gateways[$current_gateway_index]}" 2>/dev/null || ip netns exec "$NETNS_NAME" ip route change default via "${gateways[$current_gateway_index]}" 2>/dev/null
        echo -e "<$time> [\e[34mGATEWAY\e[0m] Changed: ${gateways[$current_gateway_index]} (Isolated)"
        current_gateway_index=$(( (current_gateway_index + 1) % ${#gateways[@]} ))
    fi
    mac_loop_counter=$(( (mac_loop_counter + 1) % 3 ))
    
    ultra_sysctl_harden 
    
    killall doh-client >/dev/null 2>&1
    ip netns exec "$NETNS_NAME" doh-client >/dev/null 2>&1 &
    
    user_agent
    start_tor_squid
    echo -e "<$time> [\e[34mSERVICES\e[0m] Tor/Squid direct in NETNS (RAM-Backed)"
    echo -e "<$time> [USER-AGENT] Changed: $(ip netns exec "$NETNS_NAME" cat /etc/squid/custom_user_agent | head -n 1)"
    
    start_noiser
    if ! pgrep -f "librewolf -P prophetia" >/dev/null; then
        browser
    fi
    
    log_wipe
    log_spoof
    echo -e "\e[107;34mYour internet is encrypted with 15 layers. You are anonymous! (for now) | Last change: $time\e[0m"
    echo ""
    RND_TIMEOUT=$((timeout + RANDOM % 600 - 300))
    echo ">>> Isolated: $NETNS_NAME | Timeout ~$RND_TIMEOUT Sec (RAM Disk Active)"
    notify
    sleep $RND_TIMEOUT
done
