# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff
from threading import Thread
import os
import time
import pandas

from get_ap import get_ap


def print_all():
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    """
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
    Thus we don't use channel 14.
    """
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = (ch % 13) + 1
        time.sleep(0.5)


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        packet[Dot11]
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        guessed_payload = packet[Dot11].guess_payload_class(packet)
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


INTERFACE = "wlan0mon"

AP_info = get_ap(timeout=10, interface=INTERFACE, specific_ap="Sams 9")


print(AP_info)

channel = AP_info.Channel
#BSSID = AP_info.BSSID

#change channel to be on APs channel
#os.system(f"iwconfig {INTERFACE} channel {channel}")
#clients = get_clients_on_ap(timeout=10, iface=INTERFACE, BSSID=BSSID)






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


