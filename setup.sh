#!/bin/bash


sudo pip3 install python-cfonts >/dev/null 2>&1
cd bin/
sudo pip3 install -r requirements.txt
cd ..

if command -v pacman &> /dev/null; then
    sudo pacman -S squid >/dev/null 2>&1
elif command -v apt &> /dev/null; then
    sudo apt install squid >/dev/null 2>&1
else
    echo "Non-Suported os."
fi

if command -v pacman &> /dev/null; then
    sudo pacman -S proxychains >/dev/null 2>&1
elif command -v apt &> /dev/null; then
    sudo apt install proxychains >/dev/null 2>&1
else
    echo "Non-Suported os."
fi

if command -v pacman &> /dev/null; then
    sudo pacman -S macchanger >/dev/null 2>&1
elif command -v apt &> /dev/null; then
    sudo apt install macchanger >/dev/null 2>&1
else
    echo "Non-Suported os."
fi

if command -v pacman &> /dev/null; then
    sudo pacman -S tor >/dev/null 2>&1
elif command -v apt &> /dev/null; then
    sudo apt install tor >/dev/null 2>&1
else
    echo "Non-Suported os."
fi

echo "Finish. Run 'sudo bash PropHetia.sh' command."
