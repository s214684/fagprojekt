# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff
from threading import Thread
import pandas
from wifitool import *  # LOGGER, print_all, change_channel


def callback(packet, store):
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
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)



# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)


# interface name, check using iwconfig
interface = "wlan0mon"
# start the thread that prints all the networks
printer = Thread(target=print_all)
printer.daemon = True
printer.start()

# start the channel changer
channel_changer = Thread(target=change_channel)
channel_changer.daemon = True
channel_changer.start()


# start sniffing
sniff(prn=callback, iface=interface)
