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
        fcfield = packet[Dot11].FCfield & 0x3

        # Extract to_ds and from_ds values
        to_ds = (fcfield & 0x1) != 0
        from_ds = (fcfield & 0x2) != 0

        if not to_ds and from_ds:
            # Packet is sent from AP to client
            return False
        elif to_ds and not from_ds:
            # Packet is sent from client to AP
            return True
        else:
            # Invalid configuration (e.g., ad-hoc mode)
            raise ValueError

    def _callback(packet) -> None:
        # Checks if a packet meets requirements to be
        # added as a client connected to the ap defined in get_clients_on_ap

        if packet.haslayer(Dot11):

            if _is_packet_from_client:  # type: ignore[truthy-function]
                # extract the MAC address of the client
                src_BSSID = packet[Dot11].addr1
                # check if destination address is as specified
                if packet[Dot11].addr2 == dst_BSSID:
                    client_list.append(src_BSSID)

    sniff(timeout=timeout, iface=iface, prn=_callback)

    return list(set(client_list))   
