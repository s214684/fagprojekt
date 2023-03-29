# Python Class of the client side of the scan_networks module

# Path: wifitool\scan_networks\client.py

class client:
    def __init__(self, MAC-adress, RSSI):
        self.MAC = MAC-adress
        self.RSSI: str = RSSI
        self.bitrate: int
        self.frequency_band: str