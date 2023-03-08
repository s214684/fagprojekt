from scapy.all import Dot11, sniff


def get_clients_on_ap(timeout: int, iface: str, dst_BSSID: str) -> list:
    """Function to create a list of the clients communicating with a certain AP

    Args:
        timeout (int): Time to run sniff
        iface (str): Interface to sniff on
        dst_BSSID (str): AP from which clients will be listed

    Returns:
        list: List of unique clients that are connected to the AP specified
    """

    client_list = []

    def _callback(packet) -> None:
        # Called in the scapy sniff function, checks if a packet meets requirements to be
        # added as a client connected to the ap defined in get_clients_on_ap

        if packet.haslayer(Dot11):
            # extract the to-DS/from-DS status of packet
            DS = packet[Dot11].FCfield & 0x3
            to_DS = DS & 0x1
            from_DS = DS & 0x2

            # check if sender is a client or an AP
            if to_DS == 1 and from_DS == 0:
                # extract the MAC address of the client
                src_BSSID = packet[Dot11].addr1
                # check if destination address is as specified
                if packet[Dot11].addr2 == dst_BSSID:
                    client_list.append(src_BSSID)

    sniff(timeout=timeout, iface=iface, prn=_callback)
    return list(set(client_list))
