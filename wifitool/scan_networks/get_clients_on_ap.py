from scapy.all import Dot11, sniff


def get_clients_on_ap(timeout: int, iface: str, dst_BSSID: str) -> list:
    """Function to create a list of the clients communicating with a certain AP

    Args:
        timeout (int): Time to run sniff
        iface (str): Interface to sniff
        dst_BSSID (str): AP from which clients will be listed

    Returns:
        list: List of unique clients that are connected to the AP specified
    """

    client_list = []

    def _is_packet_from_client(packet) -> bool:
        # Function to check whether the packet is sent from the client to AP
        DS = packet.FCfield & 0x3

        to_ds = DS & 0x1 != 0
        from_ds = DS & 0x2 != 0

        print("to ds:   " + str(to_ds))
        print("from ds: " + str(from_ds))
        if not to_ds and from_ds:
            # Packet is sent from AP to client
            return False
        elif to_ds and not from_ds:
            # Packet is sent from client to AP
            print("adr1: " + packet[Dot11].addr1 + "adr2: " + packet[Dot11].addr2)
            return True
        else:
            # Invalid configuration (e.g., ad-hoc mode)
            return False

    def _callback(packet) -> None:
        # Checks if a packet meets requirements to be
        # added as a client connected to the ap defined in get_clients_on_ap

        if packet.haslayer(Dot11):

            if _is_packet_from_client(packet):  # type: ignore[truthy-function]
                # extract the MAC address of the client
                src_BSSID = packet[Dot11].addr2
                # check if destination address is as specified
                if packet[Dot11].addr1 == dst_BSSID:
                    client_list.append(src_BSSID)



    sniff(timeout=timeout, iface=iface, prn=_callback)

    return list(set(client_list))




# to_ds betyder at addr1 vil være AP, og addr2 vil være client. 