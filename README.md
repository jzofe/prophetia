#     🕶️ PROPHETIA! - ENDER PROJECT [06/12/2025 - Updated!]

## < Internet connection, traffic encryptor.>
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
From the second you run the script, Prophetia builds 15+ independent anonymity layers that make correlation impossible.

1. **DNS over HTTPS + TLS**  
   all DNS queries are forced through encrypted DoH/DoT (Google, Ndo.dev, etc.). Your ISP can’t see what domains you visit.

2. **MAC address spoofing**  
   every cycle your Wi-Fi/Ethernet MAC is replaced with a random address from 21 real hardware vendors (cisco, sony, samsung, apple, etc.). you look like a completely different device.

3. **DHCP lease renewal**  
   `dhclient -r` + new request → fresh IP address every cycle. your public ip changes constantly.

4. **Router spoofing (IPv4 + IPv6)**  
   `spoofer.py` injects fake hops using real IPs belonging to Facebook, Google, NSA, Cloudflare, etc. Run `traceroute google.com`. it looks like your traffic bounces through their infrastructure.

5. **10 rotating default gateways**  
   default route jumps between 10 different public IPs (AdGuard, Quad9, Cloudflare, etc.) every cycle.

6. **eBPF/XDP kernel-level TCP fingerprint spoofing**  
   a custom eBPF program is loaded into the kernel. every outgoing tcp packet gets randomised TTL, window size, tcp options, and sequence numbers. tools like p0f, nmap, shodan, or any DPI system see a different OS/fingerprint every few seconds.

7. **Encrypted in-memory swap only**  
   physical swap is killed. a 2 GB encrypted tmpfs + dm-crypt RAM disk is created and used as swap. nothing ever touches the hard drive.

8. **New network namespace every cycle**  
   qubes-OS style isolation: a fresh network namespace + veth pair is created on every loop. even if something leaks, it dies with the namespace.

9. **Tor → I2P → Lokinet → Yggdrasil chain**  
   traffic is forced through proxychains with dynamic_chain: tor (9050) → I2P (4447) → Lokinet (1090) → Yggdrasil (20001). four completely different anonymous networks stacked on top of each other.

10. **LibreWolf in firejail sandbox**  
    a hardened “prophetia” profile is created and launched inside firejail --private. all telemetry, pings, beacons, and tracking protection are disabled by default.

11. **AI-powered human behavior randomizer**  
    an infinite background loop gently moves the mouse in natural curves, clicks randomly, and types random characters at human-like speeds. canvas, webGL, and behavioral fingerprinting services think you’re a real person.

12. **21-pass forensic-proof log wiping**  
    every cycle: journalctl vacuumed + every log file in /var/log/* + ~/.bash_history + /tmp + /var/tmp shredded with 21 passes (DoD 5220.22-M standard). Forensic recovery is impossible.

13. **Random hostname & timezone**  
   hostname becomes something like “ghost-x7f9a2k1p3” and timezone jumps between New York, London, Tokyo, Johannesburg, etc.

14. **User-Agent rotation + mitmproxy header rewriting**  
    random UA from a large real-device pool, rewritten on the fly by mitmproxy in transparent mode.

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
               +-- eBPF XDP TCP Spoof (kernel-level mutate) --+
               +-- Encrypted RAM Swap (no disk write) --+
               +-- Network Namespace (Qubes isolation) --+
               +-- Tor/I2P/Lokinet/Ygg Chain (multi-net) --+
               +-- AI Randomizer (human-like behavior) --+
               +-- Firejail Sandbox (browser isolation) --+
               +-- 21-Pass Shred (logs gone forever) --+
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
