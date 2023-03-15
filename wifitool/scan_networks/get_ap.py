import logging
import os
import sys
import time
from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff
from threading import Thread
import pandas

from utils import get_current_channel

file_handler = logging.FileHandler(filename='tmp.log')
file_handler.setLevel(level=logging.DEBUG)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers = [file_handler, stdout_handler]

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s]-{%(filename)s:%(lineno)d} %(levelname)s: %(message)s',
    handlers=handlers  # type: ignore
)
LOGGER = logging.getLogger('wifitool')
LOGGER.debug("Logger created")


def stopfilter(condition):
    if condition:
        return True
    else:
        return False


def get_ap(timeout: int, interface: str, specific_ap: str = ""):

    def _print_all():
        """
        @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
        """
        while True:
            os.system("clear")
            print(networks)
            time.sleep(0.5)

        # interface name, check using iwconfig
        # interface = interface
        # start the thread that prints all the networks
        # printer = Thread(target=print_all)
        # printer.daemon = True
        # printer.start()

    def _change_channel():
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
            time.sleep(0.5)  # TODO: Can we tune this?

    def _callback(packet):
        if packet.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            bssid = packet[Dot11].addr2
            packet[Dot11]
            # get the name of it
            ssid = packet[Dot11Elt].info.decode()
            if ssid in networks["SSID"].values or ssid.strip() == "":
                return
            try:
                dbm_signal = packet.dBm_AntSignal
            except Exception:
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

    # TODO: Save current channel
    curr_channel = get_current_channel(iface=interface)

    # start the channel changer
    channel_changer = Thread(target=_change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    if specific_ap:

        def _stopfilter(x) -> bool:
            if x[Dot11Elt].info.decode() == specific_ap:
                print("Stopping sniff. Recieved:")
                print(x)
                return True
            else:
                return False

        sniff(prn=_callback, filter="type mgt subtype beacon", iface=interface, timeout=timeout, stop_filter=_stopfilter)
        # if specific_ap not in networks.SSID: #NOT WORKING
        #    raise ValueError
        return networks[(networks.SSID == specific_ap)]

    sniff(prn=_callback, filter="type mgt subtype beacon", iface=interface, timeout=timeout)

    _change_channel
    return networks
