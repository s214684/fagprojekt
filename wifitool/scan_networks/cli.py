from scanner import Scanner
from utils import LOGGER
import datetime
import sys


def start_menu(scanner: Scanner):
    """Prints the start menu and send user to chosen menu."""
    ASCII_banner = f"""
        ░▒█░░▒█░▀█▀░▒█▀▀▀░▀█▀░░░▀▀█▀▀░▒█▀▀▀█░▒█▀▀▀█░▒█░░░
        ░▒█▒█▒█░▒█░░▒█▀▀░░▒█░░░░░▒█░░░▒█░░▒█░▒█░░▒█░▒█░░░
        ░▒▀▄▀▄▀░▄█▄░▒█░░░░▄█▄░░░░▒█░░░▒█▄▄▄█░▒█▄▄▄█░▒█▄▄█
        Time: {datetime.datetime.now()}
        By: Lucas, Nicklas & Oliver :)

        Welcome to WifiTool!
        """
    print(ASCII_banner)
    print("This tool is made in order to examine network topology and possibly exploit deauthentication frames and WEP.")
    print("The tool is made for educational purposes only and should not be used for illegal activities.")

    print("""
        Please choose what you want to do:

        1. Scan network (obtain topology)
        2. Crack WEP
        3. Options

        9. Exit (Ctrl+C)    
    """)

    action = input("Input action wanted: ").strip()

    if action == "1":
        scan_menu(scanner)
    elif action == "2":
        crack_menu(scanner)
    elif action == "3":
        options_menu(scanner)
    elif action == "9":
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid input. Try again..")
        LOGGER.info("Invalid input detected")
    start_menu(scanner)


def scan_menu(scanner: Scanner):
    """Prints the scan menu and send user to chosen action."""

    print("""
    
    SCAN MENU:

        Please choose what you want to do:
    1. Scan network
    2. Show APs
    3. Show clients
    4. Send deauth
    5. Send deauth with beacon
    6. Send beacon
    7. Save network topology

    9. Back
    """)
    action = input("Input action wanted: ").strip()

    if action == "1":
        LOGGER.info("Starting network scan...")
        scanner.scan_network()
        LOGGER.info("Network scan complete.")
    elif action == "2":
        LOGGER.info("Starting AP showcase...")
        scanner.show_aps()
        LOGGER.info("AP showcase complete.")
    elif action == "3":
        LOGGER.info("Starting client showcase...")
        scanner.show_clients()
        LOGGER.info("Client showcase complete.")
    elif action == "4":
        LOGGER.info("Starting deauth...")
        scanner.send_deauth()
        LOGGER.info("Deauth complete.")
    elif action == "5":
        LOGGER.info("Starting deauth with beacon attack...")
        scanner.send_deauth_with_beacon()
        LOGGER.info("Deauth with beacon attack complete.")
    elif action == "6":
        LOGGER.info("Starting beacon attack...")
        scanner.send_beacon()
        LOGGER.info("Beacon attack complete.")
    elif action == "7":
        LOGGER.info("Saving scan...")
        filename = input("Filename: ")
        scanner.save_scan(filename=
                            filename if filename.endswith(".json") else filename + ".json"
                            )
        LOGGER.info("Scan saved.")
    elif action == "9":
        start_menu(scanner)
    else:
        print("Invalid input. Try again..")
        LOGGER.info("Invalid input detected")

    scan_menu(scanner)


def crack_menu(scanner: Scanner):
    LOGGER.info("Starting IV scan...")
    scanner.get_ivs()
    LOGGER.info("IV scan complete.")
    start_menu(scanner)


def options_menu(scanner: Scanner) -> None:
    """Lets the user change the settings of the network scanner."""
    LOGGER.info("Entering options menu...")
    print("Current settings:")
    print(f"Timeout: {scanner.timeout}")
    print(f"Interface: {scanner.interface}")
    print("Choose what to change:")
    print("1. Timeout")
    print("2. Interface")
    print("3. Back")
    choice = input("Input choice: ")
    if choice == "1":
        timeout = int(input("Input new timeout: "))
        scanner.timeout = timeout
        LOGGER.info(f"Timeout changed to {timeout}")
    elif choice == "2":
        interface = input("Input new interface: ")
        scanner.interface = interface
        LOGGER.info(f"Interface changed to {interface}")
    elif choice == "3":
        return
    else:
        print("Invalid input. Try again..")
    options_menu(scanner)
