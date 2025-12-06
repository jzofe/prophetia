#     🕶️ PROPHETIA! - ENDER PROJECT [06/12/2025 - Updated!]

## < KERNEL-LEVEL Internet connection, traffic encryptor.>
## <BECOME A PROFESSIONAL ANONYMOUS>

OPEN - SOURCE

Connect to the internet with 15+ layers with PropHetia, no one will be able to track you!.

## 🛠️ Setup 

~~~shell
git clone https://github.com/scriptkidsensei/prophetia/
cd prophetia/
sudo bash setup.sh
# Run
sudo bash PropHetia.sh
~~~

~~~shell
usage: PropHetia.sh -c <interface> -t <timeout>
~~~

To learn your interface (lo, enp1s0, wlan0, wlo...) ;

~~~shell
ip link
~~~

And

~~~shell
sudo PropHetia.sh -c wlan0 -t <timeout (1668 second default)>
~~~

## How does it work? [15 Layer]

layer1: all DNS queries are forced through encrypted DoH/DoT (Google, Ndo.dev, etc.). Your ISP can’t see what domains you visit. 

layer2: every cycle your Wi-Fi/Ethernet MAC is replaced with a random address from 21 real hardware vendors (cisco, sony, samsung, apple, etc.). you look like a completely different device.

layer3: `dhclient -r` + new request → fresh IP address every cycle. your public ip changes constantly.

layer4: `spoofer.py` injects fake hops using real IPs belonging to Facebook, Google, NSA, Cloudflare, etc. Run `traceroute google.com`. it looks like your traffic bounces through their infrastructure. 

layer5: default route jumps between 10 different public IPs (AdGuard, Quad9, Cloudflare, etc.) every cycle.

layer6: a custom eBPF program is loaded into the kernel. every outgoing tcp packet gets randomised TTL, window size, tcp options, and sequence numbers. tools like p0f, nmap, shodan, or any DPI system see a different OS/fingerprint every few seconds.

layer7: physical swap is killed. a 2 GB encrypted tmpfs + dm-crypt RAM disk is created and used as swap. nothing ever touches the hard drive.

layer8: qubes-OS style isolation: a fresh network namespace + veth pair is created on every loop. even if something leaks, it dies with the namespace.

layer9: traffic is forced through proxychains with dynamic_chain: tor (9050) → I2P (4447) → Lokinet (1090) → Yggdrasil (20001). four completely different anonymous networks stacked on top of each other.

layer10: a hardened “prophetia” profile is created and launched inside firejail --private. all telemetry, pings, beacons, and tracking protection are disabled by default.

layer11: an infinite background loop gently moves the mouse in natural curves, clicks randomly, and types random characters at human-like speeds. canvas, webGL, and behavioral fingerprinting services think you’re a real person.

layer12: every cycle: journalctl vacuumed + every log file in /var/log/* + ~/.bash_history + /tmp + /var/tmp shredded with 21 passes (DoD 5220.22-M standard). Forensic recovery is impossible.

layer13: hostname becomes something like “ghost-x7f9a2k1p3” and timezone jumps between New York, London, Tokyo, Johannesburg, etc.

layer14: random UA from a large real-device pool, rewritten on the fly by mitmproxy in transparent mode.

layer15: the system clock inside the namespace is randomized by ±50 milliseconds, preventing tracking via ntp/clock skew analysis.

result: no stable MAC, no stable IP, no stable TCP fingerprint, no stable DNS history, no stable browser fingerprint, no logs on disk, no swap on disk, no consistent routing path.

even nation-state adversaries can’t build a reliable profile.

so you are not just hidden.  
you are a fcking ghost that changes identity every few minutes xd

~~~
+--------------+                                +------------------------+
| Application  |                                |  Recursive DNS Server  |
+-------+------+                                +-----------+------------+
        |                                                   |
+-------+------+                                +-----------+------------+
| Client side  |                                |      doh-server        |
| cache (nscd) |                                +-----------+------------+
+-------+------+                                            |
        |         +--------------------------+  +-----------+------------+
+-------+------+  |    HTTP cache server /   |  |   HTTP service muxer   |
|  doh-client  +--+ Content Delivery Network +--+ (Apache, Nginx, Caddy) |
+--------------+  +--------------------------+  +------------------------+
               +-- eBPF XDP TCP Spoof  --+
               +-- encrypted RAM Swap  --+
               +-- network Namespace  --+
               +-- tor/I2P/Lokinet/Ygg Chain --+
               +-- ai Randomizer --+
               +-- firejail Sandbox --+
               +-- 21-Pass Shred --+
~~~


For proxychain settings (don't try rn); 

~~~shell
#edit '/etc/proxychains.conf'
sudo nano /etc/proxychains.conf
#dynamic_chain, prophetia default enabled.

socks4 127.0.0.1 9050
socks5 127.0.0.1 9050
socks5 127.0.0.1 9950
~~~

- fakeroute (fakeroute)[https://github.com/blechschmidt/fakeroute/]


### Donate! buy a coffee 😭
TRON-TRX
TRC-20: TUzRVNowD4uqCjWxb59AxUWPe9YUkLZYmK

