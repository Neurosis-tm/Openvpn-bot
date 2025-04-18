Openvpn-bot

python3-full and python3-pip required:
```bash sudo apt update && sudo apt install git screen python3-full python3-pip -y ```

prepare openvpn server first, get the script, make it executable and run as sudo:

```bash curl -O https://github.com/Neurosis-tm/Openvpn/tree/main/openvpn/r-open.sh && chmod +x r-open.sh && sudo bash r-open.sh```

You need to run the script as root and have the TUN module enabled, you'll have to follow the assistant and answer a few questions to setup your VPN server.

Clone repo and install dependencies:
```bash
https://github.com/Neurosis-tm/Openvpn-bot.git
cd Openvpn-bot
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```
script run comand:
```bash screen python3 open.py ```

Contact:
https://t.me/REDHAKER

Telegram channel:
https://t.me/black_developers
