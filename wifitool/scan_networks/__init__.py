# Skal nok rykkes til et andet sted...

from scapy.all import (Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp)
import pandas as pd
from wifitool import LOGGER


def list_available_aps(packet) -> pd.DataFrame:
    """Function that is to be called from the "sniff" function as the "prn" argument which calls the function on each packet sniffed.
    The function checks whether the packet is a beacon frame, then adds the MAC address and SSID of the AP if it doesn't exist in the list.

    Example call:
        sniff(count = 100, prn = list_available_aps)
    Args:
        packet: A packet of one of the usual packet types (IP,TCP,..,)
    Returns:
        dictionary with key as MAC addresse of AP, and value as SSID of AP
    """

    LOGGER.debug("Function 'list_available_aps' is running")

    ap_list = pd.DataFrame(columns=["MAC addr", "SSID"])

    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                new_row = pd.DataFrame([packet.addr2, packet.info])
                ap_list.append(new_row)

    return ap_list


def send_beacon_frame(MAC, SSID, iface):
    """Function to send out beacon frames using a specified MAC adresse and SSID

    Args:
        MAC (str): MAC addresse of the sender.
        SSID (str): The SSID that wshows up for the targeted user.
        iface (str): Interface to send frames through
    """
    LOGGER.debug("Function 'send_beacon_frames' is running")

    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=MAC, addr3=MAC)

    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID', info=SSID, len=len(SSID))

    frame = RadioTap() / dot11 / beacon / essid

    LOGGER.info("Sending beacon frames with MAC addresse: '" + MAC + "' and SSID: '" + SSID + "' through interface: '" + iface + "'.")

    sendp(frame, iface=iface, inter=0.100, loop=1)
