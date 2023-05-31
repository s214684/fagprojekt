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

