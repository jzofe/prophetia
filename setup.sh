#!/bin/bash

echo "Prophetia Setup starting."

if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    INSTALL="sudo apt update && sudo apt install -y"
    echo "→ Debian/Ubuntu/Kali (apt)"

elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    INSTALL="sudo pacman -Syu --noconfirm"
    echo "→ Arch/Manjaro/EndeavourOS (pacman) goddamn"

elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    INSTALL="sudo dnf install -y"
    echo "→ Fedora (dnf)"

else
    echo "unsupported os, install manually pls: squid proxychains-ng macchanger tor mitmproxy firejail librewolf python-cfonts"
    exit 1
fi

PACKAGES="squid proxychains-ng macchanger tor mitmproxy firejail python-cfonts wireguard-tools"

install_librewolf() {
    case $PKG_MANAGER in
        apt)
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://deb.librewolf.net/key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/librewolf.gpg
            echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/librewolf.gpg] https://deb.librewolf.net $(lsb_release -sc 2>/dev/null || echo bookworm) main" | sudo tee /etc/apt/sources.list.d/librewolf.list
            sudo apt update
            sudo apt install -y librewolf
            ;;
        pacman)
            sudo pacman -S --noconfirm librewolf librewolf-bin 2>/dev/null || sudo pacman -S --noconfirm librewolf
            ;;
        dnf)
            sudo dnf copr enable taw/librewolf -y
            sudo dnf install -y librewolf
            ;;
    esac
}

echo "→ Packages :)"
$INSTALL $PACKAGES

echo "→ LibreWolf"
install_librewolf

echo "→ Python"
sudo pip3 install --quiet cfonts scapy daemon >/dev/null 2>&1 || sudo pip install --quiet cfonts scapy daemon

if ! command -v doh-client >/dev/null 2>&1; then
    echo "→ dns-over-https"
    mkdir -p /tmp/doh && cd /tmp/doh
    git clone https://github.com/m13253/dns-over-https.git >/dev/null 2>&1
    cd dns-over-https
    make >/dev/null 2>&1 && sudo make install >/dev/null 2>&1
    cd / && rm -rf /tmp/doh
fi

sudo sed -i 's/^ControlPort/#ControlPort/' /etc/tor/torrc 2>/dev/null || true


echo "Finish. Run 'sudo bash PropHetia.sh' command."
exit 0
