Brug
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo aireplay-ng -9 wlan0

SSID 'bridge'
Kode 'admin'
IP '192.168.1.5'
router navn 'AP_Sarah'
channel '2'
