from scanner import Scanner
from utils import LOGGER
import datetime
import sys


def start_menu(scanner: Scanner) -> None:
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


def scan_menu(scanner: Scanner) -> None:
    """Prints the scan menu and send user to chosen action."""

    if not scanner.wifis:
        LOGGER.info("Starting network scan...")
        print(f"Building topology:\nScanning network for APs and clients with timeout={scanner.timeout} on interface={scanner.interface}...")
        scanner.scan()
        scanner.show_aps()
        LOGGER.info("Network scan complete.")

    print(f"""    
    SCAN MENU
    Network topology currently consists of {len(scanner.wifis)} APs.

    Please choose what you want to do:
    1. Scan network
    2. Show APs
    3. Show clients
    4. Send deauth
    5. Save network topology as json
    6. save network topology as png

    9. Back
    """)
    action = input("Input action wanted: ").strip()

    if action == "1":
        LOGGER.info("Starting network scan...")
        print(f"Building topology:\nScanning network for APs and clients with timeout={scanner.timeout} on interface={scanner.interface}...")
        scanner.scan()
        scanner.show_aps()
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
        LOGGER.info("Saving scan as json...")
        scanner.save_scan()
        LOGGER.info("Scan saved as json.")
    elif action == "6":
        LOGGER.info("Saving scan as pdf...")
        scanner.png_scan()
        LOGGER.info("Scan saved as pdf.")
    elif action == "9":
        print("\033c")
        start_menu(scanner)
    else:
        print("Invalid input. Try again..")
        LOGGER.info("Invalid input detected")

    scan_menu(scanner)


def crack_menu(scanner: Scanner) -> None:
    """Menu for cracking WEP secret key"""
    
    print("Either scan a specific AP or load a scan to crack WEP.")
    print("1: Choose AP to scan \n2: Load scan \n3: Back")

    action = input("Input action wanted: ").strip()

    if action == "1":
        LOGGER.info("Starting IV scan...")
        scanner.get_ivs()
        LOGGER.info("IV scan complete.")
    elif action == "2":
        LOGGER.info("Starting WEP crack...")
        scanner.crack_wep()
        LOGGER.info("WEP crack complete.")
    elif action == "3":
        LOGGER.info("Returning to start menu")
        print("Returning to start menu...")
        start_menu(scanner)
    else:
        print("Invalid input. Try again..")
        LOGGER.info("Invalid input detected")
    crack_menu(scanner)


def options_menu(scanner: Scanner) -> None:
    """Lets the user change the settings of the network scanner."""
    LOGGER.info("Entering options menu...")
    print(f"""\nCurrent settings:
    Timeout: {scanner.timeout}
    Interface: {scanner.interface}
    Choose what to change:
        1. Timeout
        2. Interface
        3. Back""")
    choice = input("Input choice: ")
    if choice == "1":
        timeout = int(input("Input new timeout: ").strip())
        scanner.timeout = timeout
        LOGGER.info(f"Timeout changed to {timeout}")
    elif choice == "2":
        interface = input("Input new interface: ").strip()
        scanner.interface = interface
        LOGGER.info(f"Interface changed to {interface}")
    elif choice == "3":
        print("\033c")
        return
    else:
        print("Invalid input. Try again..")
    options_menu(scanner)
