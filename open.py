import telebot
import os
import time
import psutil
import subprocess
import shutil
import re
import tempfile
import subprocess
import glob
from datetime import datetime
from telebot import types
import dotenv

dotenv.load_dotenv()
TOKEN = input('Tokeniňizi ýazyň:')
ADMIN_IDS = input('Admin id:')

bot = telebot.TeleBot(TOKEN)
script_dir = os.path.dirname(os.path.abspath(__file__))

def open_as_sudo(path):
    return os.popen(f'sudo cat {path}', 'r')

def vpn_log():
    with open_as_sudo('/var/log/openvpn/status.log') as f:
        lines = f.readlines()
    lines = lines[:lines.index('GLOBAL STATS\n')]
    return ''.join(lines)

def restart_vpn():
    os.system('sudo systemctl restart openvpn@server')

def admin_required(func):
    def wrapper(message):
        if str(message.chat.id) not in ADMIN_IDS:
            bot.reply_to(message, "Bu buýrugy ýerine ýetirmäge rugsadyňyz ýok.")
            return
        return func(message)
    return wrapper

def c2c_status():
    
    with open_as_sudo('/etc/openvpn/server.conf') as file:
        lines = file.readlines()

    if 'client-to-client\n' not in lines:
        return 'disabled'
    elif 'client-to-client\n' in lines:
        return 'enabled'

def manage_client_to_client(switch):
    assert switch in ['enable', 'disable'], "Nädogry argument. Diňe 'işletmek' ýa-da 'öçürmek' rugsat edilýär."

    with open('/etc/openvpn/server.conf', 'r') as file:
        lines = file.readlines()

    if switch == 'enable':
        os.system('sudo iptables -D FORWARD -i tun0 -o tun0 -j DROP')
        os.system('sudo iptables -D INPUT -i tun0 -j DROP')
        os.system('sudo iptables -D OUTPUT -o tun0 -j DROP')
        os.system('sudo iptables -D INPUT -i tun0 -s 10.8.0.1 -j ACCEPT')
        os.system('sudo iptables -D OUTPUT -o tun0 -d 10.8.0.1 -j ACCEPT')
        os.system('sudo iptables -P INPUT ACCEPT')
        os.system('sudo iptables -P FORWARD ACCEPT')
        os.system('sudo iptables -P OUTPUT ACCEPT')
        lines.append('client-to-client\n')
    elif switch == 'disable':
        os.system('sudo iptables -A FORWARD -i tun0 -o tun0 -j DROP')
        os.system('sudo iptables -A INPUT -i tun0 -j DROP')
        os.system('sudo iptables -A OUTPUT -o tun0 -j DROP')
        os.system('sudo iptables -A INPUT -i tun0 -s 10.8.0.1 -j ACCEPT')
        os.system('sudo iptables -A OUTPUT -o tun0 -d 10.8.0.1 -j ACCEPT')
        lines.remove('client-to-client\n')

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
        for line in lines:
            temp.write(line)
        temp_path = temp.name

    os.system(f'sudo mv {temp_path} /etc/openvpn/server.conf')
    time.sleep(1)
   


def get_server_ip():
    command = "cat /etc/openvpn/client-template.txt | grep -E 'remote ' | awk '{printf $2 \":\" $3 \"\\n\"}'"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    if error:
        print(f"An error occurred: {error}")
    else:
        return output.decode('utf-8').strip()
    
def newClient(name):
    CLIENT = name
    PASS = '1'
    with open_as_sudo('/etc/openvpn/easy-rsa/pki/index.txt') as f:
        CLIENTEXISTS = f.read().count(f"/CN={CLIENT}\n")

    if CLIENTEXISTS == 1:
        print("Görkezilen müşderi CN eýýäm aňsat-rsa tapyldy, başga bir at saýlaň.")
        return
    else:
        os.chdir('/etc/openvpn/easy-rsa/')
        if PASS == '1':
            subprocess.run(['sudo', './easyrsa', '--batch', 'build-client-full', CLIENT, 'nopass'])
        print(f"Client {CLIENT} added.")

    if os.system('sudo grep -qs "^tls-crypt" /etc/openvpn/server.conf') == 0:
        TLS_SIG = "1"
    elif os.system('sudo grep -qs "^tls-auth" /etc/openvpn/server.conf') == 0:
        TLS_SIG = "2"

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
        temp.write(open_as_sudo("/etc/openvpn/client-template.txt").read())
        temp.write("<ca>\n")
        temp.write(open_as_sudo("/etc/openvpn/easy-rsa/pki/ca.crt").read())
        temp.write("</ca>\n")
        temp.write("<cert>\n")
        temp.write(open_as_sudo(f"/etc/openvpn/easy-rsa/pki/issued/{CLIENT}.crt").read())
        temp.write("</cert>\n")
        temp.write("<key>\n")
        temp.write(open_as_sudo(f"/etc/openvpn/easy-rsa/pki/private/{CLIENT}.key").read())
        temp.write("</key>\n")

        if TLS_SIG == "1":
            temp.write("<tls-crypt>\n")
            temp.write(open_as_sudo("/etc/openvpn/tls-crypt.key").read())
            temp.write("</tls-crypt>\n")
        elif TLS_SIG == "2":
            temp.write("key-direction 1\n")
            temp.write("<tls-auth>\n")
            temp.write(open_as_sudo("/etc/openvpn/tls-auth.key").read())
            temp.write("</tls-auth>\n")

    os.system(f'sudo mv {temp.name} {os.path.join(script_dir, f"{CLIENT}.ovpn")}')

    print(f"openýpn kody döredildi {script_dir}/{CLIENT}.ovpn.")
    print(".Ovpn faýlyny göçürip alyň we OpenVPN müşderiňize import ediň.")

def revoke_client(name):

    if not os.path.isfile(f'{name}.ovpn'):
        return "User does not exist."
    
    os.chdir('/etc/openvpn/easy-rsa/')
   
    with open_as_sudo('/etc/openvpn/easy-rsa/pki/index.txt') as f:
        if f"V.*CN={name}" not in f.read():
            print("A client with this name does not exist.")
   
    subprocess.call(f'sudo ./easyrsa --batch revoke {name}', shell=True)
   
    subprocess.call('sudo EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl', shell=True)
   
   
    subprocess.call('sudo cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem', shell=True)
    
    subprocess.call('sudo chmod 644 /etc/openvpn/crl.pem', shell=True)
    
    for root, dirs, files in os.walk('/home/'):
        for file in files:
            if file == f"{name}.ovpn":
                subprocess.call(f'sudo rm {os.path.join(root, file)}', shell=True)
    if os.path.isfile(f"/root/{name}.ovpn"):
        subprocess.call(f'sudo rm /root/{name}.ovpn', shell=True)
   
    with open_as_sudo('/etc/openvpn/ipp.txt') as f:
        lines = f.readlines()
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
        for line in lines:
            if line.strip("\n") != f"{name}":
                temp.write(line)
   
    os.system(f'sudo mv {temp.name} {"/etc/openvpn/ipp.txt"}')
    
    subprocess.call('sudo cp /etc/openvpn/easy-rsa/pki/index.txt /etc/openvpn/easy-rsa/pki/index.txt.bk', shell=True)
    return "Müşderi üçin sertifikaty ýatyryldy."

commands = [
    types.BotCommand('new', 'täze kot döretmek'),
    types.BotCommand('revoke', 'kody öçürmek'),
    types.BotCommand('c2c', 'müşderi-müşderi traffigini işjeňleşdirmek / öçürmek'),
    types.BotCommand('restart', 'vpn serverine restart bermek'),
    types.BotCommand('info', 'serweriň ýagdaýyny barlaň'),
]
bot.set_my_commands(commands)

@bot.message_handler(commands=['start'])

def start(message):
    bot.send_message(message.chat.id, "Openvpn-access-bot-a hoş geldiňiz! \ Menýuda elýeterli buýruklaryň sanawyny görüp bilersiňiz")

@bot.message_handler(commands=['new'])
@admin_required
def new_user(message):
    os.chdir(script_dir)
    msg = bot.reply_to(message, "Täze kot adyny dogry formatda giriziň [a-zA-Z0-9]:")
    bot.register_next_step_handler(msg, create_new_user)

def create_new_user(message):
    date_prefix = datetime.now().strftime('%d_%m')
    if not re.match("^[a-zA-Z0-9]*$", message.text):
        bot.reply_to(message, "Nädogry giriş formaty Buýrugy täzeden giriziň we ady dogry formatda giriziň.")
        return
    name = message.text + '_' + date_prefix
    if os.path.isfile(f'{name}.ovpn'):
        bot.reply_to(message, "Ulanyjy eýýäm bar. Ine açar faýl:")
        bot.send_document(message.chat.id, open(f'{name}.ovpn', 'rb'))
    else:
        newClient(name)
        os.chdir(script_dir)
        bot.reply_to(message, 'Ulanyjy döredildi. Ine açar faýl:')
        bot.send_document(message.chat.id, open(f'{name}.ovpn', 'rb'))

@bot.message_handler(commands=['revoke'])
@admin_required
def revoke_user(message):
    os.chdir(script_dir)
    users = [os.path.splitext(os.path.basename(file))[0] for file in glob.glob('*.ovpn')]
    bot.reply_to(message, "Users list:\n" + '\n'.join(users))
    msg = bot.reply_to(message, "kody öçürmek ulanyjy adyny giriziň:")
    bot.register_next_step_handler(msg, revoke_process)

def revoke_process(message):
    if message.text.startswith('/'):
        bot.reply_to(message, "Nädogry giriş formaty Buýrugy täzeden giriziň we ady gerekli formatda giriziň.")
        return
    name = message.text
    if not os.path.isfile(f'{name}.ovpn'):
        bot.reply_to(message, "Ulanyjy ýok.")
    else:
        revoke_client(name)
        bot.reply_to(message, "Ulanyjy öçürüldi.")

@bot.message_handler(commands=['c2c'])
@admin_required
def c2c_traffic(message):
    status = c2c_status()
    markup = types.InlineKeyboardMarkup()
    itembtn1 = types.InlineKeyboardButton('Enable' if status == 'disabled' else 'Disable', callback_data='change_c2c_status')
    markup.add(itembtn1)

    bot.send_message(message.chat.id, f"Müşderiniň häzirki ýagdaýy: {status}. Muny üýtgetmek isleýärsiňizmi?", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == 'change_c2c_status')
def change_c2c_status(call):
    current_status = c2c_status()
    new_status = 'enable' if current_status == 'disabled' else 'disable'
    manage_client_to_client(new_status)
    bot.answer_callback_query(call.id, f"c2c ýagdaýy üýtgedildi: {new_status}")
    bot.delete_message(call.message.chat.id, call.message.message_id)

@bot.message_handler(commands=['restart'])
@admin_required
def restart_server(message):
    markup = types.InlineKeyboardMarkup()
    itembtn1 = types.InlineKeyboardButton('Restart vpn server', callback_data='restart')
    markup.add(itembtn1)
    bot.send_message(message.chat.id, f"really??", reply_markup=markup)
@bot.callback_query_handler(func=lambda call: call.data == 'restart')
def restart(call):
    bot.answer_callback_query(call.id, f"restarted!")
    bot.delete_message(call.message.chat.id, call.message.message_id)
    restart_vpn()


@bot.message_handler(commands=['info'])
@admin_required
def server_stat(message):
    os.chdir(script_dir)
    
    cpu_usage = psutil.cpu_percent(interval=1)
   
    memory_info = psutil.virtual_memory()
    total_memory = memory_info.total / (1024.0 ** 2)
    used_memory = memory_info.used / (1024.0 ** 2)
    memory_percent = memory_info.percent

    
    disk_info = psutil.disk_usage('/')
    total_disk = disk_info.total / (1024.0 ** 3)
    used_disk = disk_info.used / (1024.0 ** 3)
    disk_percent = disk_info.percent

   
    try:
        vpn_status = subprocess.check_output(['systemctl', 'is-active', 'openvpn@server'])
        vpn_status = 'active'
    except subprocess.CalledProcessError:
        vpn_status = 'inactive'

   
    net_io_counters = psutil.net_io_counters()

    
    bytes_sent_mb = net_io_counters.bytes_sent / (1024 * 1024)
    bytes_recv_mb = net_io_counters.bytes_recv / (1024 * 1024)

    vpn_clients = vpn_log()
    server_ip = get_server_ip()
    traffic_c2c = c2c_status()

    
    bot.reply_to(message, f"CPU load: {cpu_usage}%\n"
                          f"RAM used: {used_memory:.1f}MB of {total_memory:.1f}MB ({memory_percent}%)\n"
                          f"Disk space used: {used_disk:.1f}GB of {total_disk:.1f}GB ({disk_percent}%)\n"
                          f"OpenVPN status: {vpn_status} {server_ip}\n\n{vpn_clients}\n"
                          f"Client_2_Client: {traffic_c2c}\n\n"
                          f"System network I/O statistics:\n"
                          f"Sent: {bytes_sent_mb:.1f}MB\n"
                          f"Received: {bytes_recv_mb:.1f}MB"
                          )

while True:
    try:
        bot.polling(none_stop=True)
    except Exception as e:
        print('Birikdiriş aralygy, 15 sekuntdan soň täzeden birikdiriň ...')
        time.sleep(15)
