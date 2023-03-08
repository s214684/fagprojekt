from scapy.all import Dot11, sniff


def get_clients_on_ap(timeout: int, iface: str, dst_BSSID: str) -> list:

    client_list = []

    def _callback(packet):
        if packet.haslayer(Dot11):
            # extract the MAC address of the client
            src_BSSID = packet[Dot11].addr2

            # check if destination address is as specified
            if packet[Dot11].addr1 == dst_BSSID:
                client_list.append(src_BSSID)

    sniff(timeout=timeout, iface=iface, prn=_callback)

    return list(set(client_list))
