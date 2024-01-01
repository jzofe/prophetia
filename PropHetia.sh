#!/bin/bash


# ENDER PROJECT
# OPEN-SOURCE
# BECOME A PROFESSIONAL ANONYMOUS. 
# Prophetia >>> <Internet connection, traffic encryptor. And anon email sender.>

# Coded By FYKS

if [ "$EUID" -ne 0 ]; then
  echo "Permission required. Type 'sudo Prophetia.sh'."
  exit 1
fi

dohpage="/etc/dns-over-https/doh-client.conf"
interface="wlan0"
dns_server="dns://84.200.69.80"
target_ip="121.19.5.2"
timeout="1668"
subject_mail="0"
message_mail="0"
recipient_email="0"
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

usage() {
  echo "usage: $0 -c <interface> -d <disk> -t <timeout>"
  echo "for anon-email: $0 -e <recipient_mail> -s <subject> -m <messsage> "
  exit 1
}


encrypt_mail() {
  gpg --gen-key

  recipient_email="$recipient_email"
  subject="$subject_mail"
  message="$message_mail"
  echo "$message" > prophetia_anon_mail.txt
  gpg --encrypt --recipient "$recipient_email" --output encrypted_message.gpg prophetia_anon_mail.txt
  mail -s "$subject" -a encrypted_message.gpg "$recipient_email" < prophetia_anon_mail.txt
  rm temp_message.txt encrypted_message.gpg
  echo "Mail send!"
}


reqrograms=("mitmproxy" "macchanger" "squid" "proxychains" "tor")

check() {
  command -v $1 >/dev/null 2>&1
}

install() {
  clear
  echo "Installing.."
  if [ -x "$(command -v apt-get)" ]; then
    sudo apt-get install -y $1 >/dev/null 2>&1
  elif [ -x "$(command -v pacman)" ]; then
    sudo pacman -S --noconfirm $1 >/dev/null 2>&1
  else
    echo "Unsupported package manager. Please install '$1' manually."
    exit 1
  fi
}

for program in "${reqrograms[@]}"; do
  if check $program; then
    echo ""
  else
    install $program
  fi
done

while getopts ":c:t:d:e:s:m:" opt; do
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
    s )
      subject=$OPTARG
      ;;
    m )
      message=$OPTARG
      ;;
    e )
      encrypt_mail
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
  proxies=$(curl -s "https://free-proxy-list.net/#list")
  echo "$proxies" > /etc/squid/proxy_list.txt
}

random_proxys() {
  rand_proxy=$(shuf -n 1 /etc/squid/proxy_list.txt)
  echo "$rand_proxy" | tr -d '[:space:]'
}

uuid() {
  disk_partition="$disk"

  sudo tune2fs $disk_partition -U random > /dev/null 2>&1
}


dhcp() {
  sudo dhclient -r > /dev/null 2>&1
  sudo dhclient > /dev/null 2>&1
}
get_mac() {
 sudo ifconfig "$1" | awk '/ether/ {print $2}'
}

routerspoof() {
    sudo ifconfig "$1" | awk '/ether/ {print $2}'
    INTERFACE_MAC=$(get_mac "$interface")
    ROUTER_MAC=$(get_mac "router_interface")
    sudo sed -i "32s/ROUTER_MAC = \".*\"/ROUTER_MAC = \"$ROUTER_MAC\"/" spoofer.py
    sudo sed -i "33s/INTERFACE_MAC = \".*\"/INTERFACE_MAC = \"$INTERFACE_MAC\"/" spoofer.py
    cd ..
    sudo bash iptables.sh >/dev/null 2>&1
    sudo python3 spoofer.py >/dev/null 2>&1
}

browser() {
   sudo systemctl start tor >/dev/null 2>&1
   sudo system tor start >/dev/null 2>&1

   sed -i '10s/^# //' -i '18s/^/# /' /etc/proxychains.conf >/dev/null 2>&1
   echo "socks5 127.0.0.1:53" >> /etc/proxychains.conf >/dev/null 2>&1

   proxychains firefox -CreateProfile "prophetia" >/dev/null 2>&1
   proxychains firefox -P prophetia -no-remote about:config >/dev/null 2>&1
   proxychains firefox -P prophetia -no-remote about:config >/dev/null 2>&1
   sed -i 's/privacy.donottrackheader.enabled.*/privacy.donottrackheader.enabled=true/' ~/.mozilla/firefox/prophetia6/prefs.js
   sed -i 's/privacy.clearOnShutdown.cookies.*/privacy.clearOnShutdown.cookies=true/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/privacy.clearOnShutdown.history.*/privacy.clearOnShutdown.history=true/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/browser.send_pings.*/browser.send_pings=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/beacon.enabled.*/beacon.enabled=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/browser.safebrowsing.downloads.remote.enabled.*/browser.safebrowsing.downloads.remote.enabled=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/browser.safebrowsing.blockedURIs.enabled.*/browser.safebrowsing.blockedURIs.enabled=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/toolkit.telemetry.unified.*/toolkit.telemetry.unified=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/toolkit.telemetry.enabled.*/toolkit.telemetry.enabled=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/toolkit.telemetry.server.*/toolkit.telemetry.server=""/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/datareporting.healthreport.uploadEnabled.*/datareporting.healthreport.uploadEnabled=false/' ~/.mozilla/firefox/prophetia/prefs.js
   sed -i 's/datareporting.policy.dataSubmissionEnabled.*/datareporting.policy.dataSubmissionEnabled=false/' ~/.mozilla/firefox/prophetia/prefs.js

}


log() {
  sudo journalctl --vacuum-size=10M > /dev/null 2>&1
  sudo truncate -s 0 /var/log/syslog > /dev/null 2>&1
  sudo truncate -s 0 /var/log/auth.log > /dev/null 2>&1
  sudo truncate -s 0 /var/log/dmesg  > /dev/null 2>&1
  history -c  > /dev/null 2>&1
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


  prefix_list=("08:00:46" "00:07:0e" "fc:fb:fb" "fc:fa:f7" "f8:c6:78" "f4:7f:35" "f0:37:a1" "ec:43:f6" "e8:9a:ff" "e8:5b:f0" "e4:d5:3d" "e0:ee:1b" "dc:85:de" "00:50:56" "3c:df:bd" "64:34:09" "50:a4:c8" "40:22:ed" "38:26:cd" "30:89:99" "00:41:b4")

  random_index=$((RANDOM % ${#prefix_list[@]}))

  selected_prefix=${prefix_list[$random_index]}

  random_mac=$(printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))


  vendor_name=${vendor_dict[$selected_prefix]}
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
  echo "Settings restored."
}

trap 'res_settings; exit 1' INT TERM

v5() {
    sleep "$1"
}
clear
echo "< interface: $interface"
echo "< disk: $disk"
echo "< timeout: $timeout"
echo ""
v5 2
echo ""

cd bin/

sudo mkdir DOH > /dev/null 2>&1

cd DOH/

git clone https://github.com/m13253/dns-over-https > /dev/null 2>&1

cd dns-over-https/

make > /dev/null 2>&1

sudo make install > /dev/null 2>&1

sudo sed -i '23s/^/# /' "$doh_page" > /dev/null 2>&1
sudo sed -i '24s/^/# /' "$doh_page" > /dev/null 2>&1
sudo sed -i '29s#url = "[^"]*"#url = "https://dns.ndo.dev/dns-query"#' "$doh_page"
sudo sed -i '68s/"[^"]*"/"185.181.61.24:53"/' "$doh_page"
sudo sed -i '69s/"[^"]*"/"81.169.136.222:53"/' "$doh_page"

sudo systemctl start doh-client.service > /dev/null 2>&1
sudo systemctl enable doh-client.service > /dev/null 2>&1

echo "<<< HTTP and DNS traffic is being encrypted. Please wait. Note: This script will highly restrict the internet for anonymity purpose. Some things may not work!"
v5 15
sudo touch /etc/squid/custom_user_agent
sudo systemctl start dbus
sudo service squid start > /dev/null 2>&1

proxys

sudo iptables -P FORWARD DROP > /dev/null 2>&1

sudo iptables -P OUTPUT ACCEPT > /dev/null 2>&1

sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT > /dev/null 2>&1

sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT > /dev/null 2>&1

sudo iptables -A INPUT -i lo -j ACCEPT > /dev/null 2>&1

sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 3128 > /dev/null 2>&1

echo "https_port 3129 intercept ssl-bump cert=/etc/squid/ssl_cert/myCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB"

echo "Finished. PropHetia Starting..."


while true; do
  time=$(date +"%H:%M:%S")
  clear && cfonts Prophetia -a center -f simple3d -c gray && echo -e "\e[1m                                                        Prophetia - Be anonymous! | [<enderproject>]\e[0m"  && echo ""

  echo "--time--    --changes--"
  echo -e "<$time> [\e[34m\e[1mMAC\e[0m] Adress changed. New MAC: '\e[31m\e[1m$(macchanger -s $interface | awk '/Current MAC/{print $3}')\e[0m'"
  v5 2
  dhcp
  time=$(date +"%H:%M:%S")
  echo -e "<$time> [\e[34m\e[1mDHCP\e[0m] are encrypted."
  
  messag2="Prophetia: DHCP encrypted! Timeout : $timeout"
  notify-send "Prophetia Notification" "$messag2"
  dns
  echo -e "<$time> [\e[34m\e[1mDNS\e[0m] are encrypted."
  v5 2
  routerspoof
  v5 2
  echo "<$time> [\e[34m\e[1mROUTER\e[0m] Spoofed (IPv6 + IPv4)"
  sudo ip route add default via "${gateways[$current_gateway_index]}"
  
  echo -e "<$time> [\e[34m\e[1mGATEWAY\e[0m] Changed. New GATEWAY : '\e[31m\e[1m${gateways[$current_gateway_index]}\e[0m'"
  current_gateway_index=$(( (current_gateway_index + 1) % ${#gateways[@]} ))
  
  messag5="Prophetia: Gateway changed Timeout : $timeout"
  
  notify-send "Prophetia Notification" "$messag5"
  v5 2
  time=$(date +"%H:%M:%S")
  
  echo -e "<$time> [Limit] Network connection limited."
  
  v5 1
  echo -e "<$time> [\e[34m\e[1mUUID\e[0m] Disk UUID changed."
  v5 1
  
  sudo service squid restart > /dev/null 2>&1
  mitmproxy --mode transparent --modify-headers ":~b'User-Agent:.*' -> 'User-Agent: $(cat /etc/squid/custom_user_agent)'" > /dev/null 2>&1
  user_agent
  time=$(date +"%H:%M:%S")
  echo -e "<$time> [\e[35m\e[1mUSER-AGENT\e[0m] Changed. New User Agent: '\e[34m$(cat /etc/squid/custom_user_agent)\e[0m'"
  v5 2
  
  proxy=$(random_proxys)
  
  sed -i "s/http_port 3128/http_port 3128\nacl my_acl src $proxy/g" /etc/squid/squid.conf
  echo -e "<$time> [\e[30m\e[1mPROXY\e[0m] Changed. New PROXY : $proxy"
  v5 2
  echo -e "<$time> [\e[34m\e[1mTOR\e[0m] tor connection encrypted. Socks5 and socks4 Dyanmic CHAIN active. "
  browser
  echo ""
  
  echo "[FIREFOX] browser settings are being processed, please wait."
  v5 4
  
  echo -e "[FIREFOX] Firefox has been started and security settings have been adjusted. Let the action begin :)"
  v5 2
  log
  
  echo "[LOGS] ALL system logs cleared."
  
  v5 1
  echo ""

  time=$(date +"%H:%M:%S")
  echo -e "\e[107;34mYour internet is encrypted with 7 layers. You are anonymous! (for now) | Last change: $time\e[0m"
  echo ""
  echo ">>> Timeout : $timeout Sec"

  notify

  sleep $timeout

done

res_settings
