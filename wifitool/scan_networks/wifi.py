from typing import Union


class Wifi:
    """Class to represent a wifi network."""
    def __init__(self, SSID, BSSID, dBm_signal, channel, crypto, max_bitrate: int = 0, country: str = "", beacon_interval: int = 0):
        self.SSID: str = SSID
        self.BSSID: str = BSSID
        self.dBm_signal: str = dBm_signal
        self.channel: int = channel
        self.crypto: str = crypto
        self.beacon_interval: Union[int, None] = None if beacon_interval == 0 else beacon_interval
        self.max_bitrate: Union[int, None] = None if max_bitrate == 0 else max_bitrate
        self.country: Union[str, None] = None if not country else country
        self.clients: list[str] = []

    def __eq__(self, other) -> bool:
        # Dunder for comparing two Wifi objects
        if (isinstance(other, Wifi)):
            return self.SSID == other.SSID
        return False

    def __str__(self) -> str:
        return self.SSID

    def __repr__(self) -> str:
        # Dunder for printing a Wifi object
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
