# Python Class of the client side of the scan_networks module

# Path: wifitool\scan_networks\client.py

class client:
    def __init__(self, MAC-adress, RSSI, channel, crypto):
        self.MAC = MAC-adress
        self.RSSI: str = RSSI
        self.channel: int = channel
        self.bitrate: int
        self.frequency_band: str
        self.clients: list[str] = []