#     🕶️ PROPHETIA! - ENDER PROJECT

## < Internet connection, traffic encryptor. And anon email sender>
## <BECOME A PROFESSIONAL ANONYMOUS>

Connect to the internet with 7+ layers with PropHeita, no one will be able to track you!.

## 🛠️ Setup 

~~~shell
git clone https://github.com/scriptkidsensei/prophetia/
cd prophetia/
sudo bash setup.sh
# Run
sudo bash PropHetia.sh
~~~

~~~shell
usage: PropHetia.sh -c <interface> -d <disk> -t <timeout>
for anon-email: PropHetia.sh -e <recipient_mail> -s <subject> -m <messsage>
~~~

To learn your interface (lo, enp1s0, wlan0, wlo...) ;

~~~shell
ip link
~~~

And

~~~shell
sudo PropHetia.sh -c wlan0 -d <disk (usually /dev/sda1)> -t <timeout (1668 second default)>
~~~

## How does it work?

Prophetia encrypts your HTTP and DNS traffic from the moment it is executed, a process known as DNS OVER HTTPS (DoH). The script contains three different DoH servers. After starting the DoH service, certain iptables commands are executed. These commands redirect ports that could be deemed "dangerous" to different protocols. Following this, the MAC address of your entered Wi-Fi/ethernet adapter interface is spoofed randomly from among 23 VENDOR addresses I have added. The DHCP address is renewed with the "client -r" (random) command. Router spoofing is carried out with the "spoofer.py" script in the folder where Prophetia is located. This script works quite interestingly and magnificently, operating through IP addresses such as FACEBOOK, NSA, and GOOGLE, supporting both IPv6 and IPv4. When you enter a website, your router first connects to the ISP. The ISP then establishes connections with other external ISP routers, and together with these routers, a connection is made to the web server. You can view this process step by step with the "traceroute google.com" command in Linux. By adding extra router addresses to the router with this script, we create complexity, and Prophetia contains 10 gateways. I have kept the command to spoof the Disk UUID address, which I added to the script, disabled because it causes some issues (such as GRUB errors). I will fix this soon! A connection is established to a proxy address with Squid, and through this proxy address, a connection is made to proxychains. Proxychains operates over the tor connection (127.0.0.1:53) and both socks4 and socks5 have been added to proxychains. Then the Firefox browser is opened, and a profile named "prophetia" is created. Some security settings I added to the script are applied to this profile, including "donottrack," etc. Afterward, system logs are deleted, which consist of "/var/log/syslog, /var/log/auth.log, /var/log/dmesg," and, of course, terminal logs are also erased. After all these processes, your internet speed will decrease by approximately 8-10 Mbps.

- fakeroute (fakeroute)[https://github.com/blechschmidt/fakeroute/]
