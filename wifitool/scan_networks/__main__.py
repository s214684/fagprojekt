# Get SSIDS in wifi medium (scan network)

# Choose one SSID to emulate - e.g. based on WPA2, name, number of clients connected to it

# Can we crack the key in order to create our own AP? if not go to next..

# Create rogue AP with same SSID+key

# Send beacon frames where we look like good AP (but we are the bad AP)

# De-auth clients connected to SSID

# Let clients connect to our rogue AP

from scanner import Scanner
from utils import get_iface, check_system
from wifi import Wifi
import sys
from deauth import deauth
import datetime
import pprint

check_system()
INTERFACE = get_iface()
TIMEOUT = 20


# Create terminal menu for user to choose what to do
def prompt_menu(welcome: bool = False, start: bool = False):
    if welcome:
        ASCII_banner = f"""
        ░▒█░░▒█░▀█▀░▒█▀▀▀░▀█▀░░░▀▀█▀▀░▒█▀▀▀█░▒█▀▀▀█░▒█░░░
        ░▒█▒█▒█░▒█░░▒█▀▀░░▒█░░░░░▒█░░░▒█░░▒█░▒█░░▒█░▒█░░░
        ░▒▀▄▀▄▀░▄█▄░▒█░░░░▄█▄░░░░▒█░░░▒█▄▄▄█░▒█▄▄▄█░▒█▄▄█
        Time: {datetime.datetime.now()}
        By: Lucas, Nicklas & Oliver :)

        Welcome to WifiTool!
        """
    else:
        ASCII_banner = ""

    if start:
        string_to_show = f"""
        {ASCII_banner}
        Please choose what you want to do:

        1. Scan network
        2. Get clients on AP
        3. Options

        9. Exit (Ctrl+C)

        """
    else:
        string_to_show = f"""
    {ASCII_banner}
    Please choose what you want to do:

    1. Show APs
    2. Show clients
    3. Send deauth

    8. Back to start
    9. Exit (Ctrl+C)

    """

    print(string_to_show)

    action = input("Input action wanted: ").strip()
    action = "a." + action if start else "b." + action
    return action


def scan_network() -> bool:
    print("Scanning network for APs...")
    AP_info = scanner.scan_for_aps(timeout=TIMEOUT)
    print(AP_info)
    # print(scanner.wifis)

    # scan network for clients as well
    print("Scanning network for clients...")
    scanner.scan_for_clients(timeout=TIMEOUT)
    pp = pprint.PrettyPrinter(depth=4)
    pp.pprint(scanner.get_clients())


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


def options():
    # Let user set constants such as timeout and interface
    global TIMEOUT
    global INTERFACE
    print("Current settings:")
    print(f"Timeout: {TIMEOUT}")
    print(f"Interface: {INTERFACE}")
    print("Choose what to change:")
    print("1. Timeout")
    print("2. Interface")
    print("3. Back")
    choice = input("Input choice: ")
    if choice == "1":
        TIMEOUT = int(input("Input new timeout: "))
        options()
    elif choice == "2":
        INTERFACE = input("Input new interface: ")
        options()
    elif choice == "3":
        return
    else:
        print("Invalid input. Try again..")
        options()


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
                options()
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
