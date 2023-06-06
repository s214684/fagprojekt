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

    def get_clients_MAC(self) -> str:
        """Function to get all clients connected to the AP in a nice newline seperated string format

        Returns:
            str: of all clients connected to the AP
        """
        return "\n".join(self.clients)

    def details(self) -> str:
        """Function to get all details that has a value and return them in a nice newline seperated string format

        Returns:
            str: of all details that has a value
        """
        return "\n".join([f"{key}: {value}" for key, value in self.__dict__.items() if value])
