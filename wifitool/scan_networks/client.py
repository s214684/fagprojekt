# Python Class of the client side of the scan_networks module

# Path: wifitool\scan_networks\client.py

class Client:
    def __init__(self, MAC_adress, RSSI):
        self.MAC = MAC_adress
        self.RSSI: str = RSSI
        self.bitrate: int
        self.frequency_band: str
