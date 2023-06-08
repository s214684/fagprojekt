from scanner import Scanner
from utils import check_system
import sys
from cli import prompt_menu, options
from wifitool import LOGGER
INTERFACE = check_system()
TIMEOUT = 20

with Scanner(INTERFACE, TIMEOUT) as scanner:
    scanner = scanner
    LOGGER.info("Starting WifiTool...")
    # Clear screen
    print("\033c")
    start = True
    try:
        action = prompt_menu(welcome=True, start=True)
        while True:
            # Clear screen
            start = False
            if action == "a.1":
                LOGGER.info("Starting network scan...")
                scanner.scan_network()
                LOGGER.info("Network scan complete.")
            elif action == "a.2" or action == "b.2":
                LOGGER.info("Starting client scan...")
                scanner.show_clients()
                LOGGER.info("Client scan complete.")
            elif action == "b.1":
                LOGGER.info("Starting AP showcase...")
                scanner.show_aps()
                LOGGER.info("AP showcase complete.")
            elif action == "b.3":
                LOGGER.info("Starting deauth attack...")
                scanner.send_deauth()
                LOGGER.info("Deauth attack complete.")
            elif action == "b.4":
                LOGGER.info("Starting deauth with beacon attack...")
                scanner.send_deauth_with_beacon()
                LOGGER.info("Deauth with beacon attack complete.")
            elif action == "a.3":
                LOGGER.info("Options menu opening.")
                options(scanner)
                LOGGER.info("Options menu closed.")
                start = True
            elif action == "b.5":
                LOGGER.info("Starting IV scan...")
                scanner.get_ivs()
                LOGGER.info("IV scan complete.")
            elif action == "b.6":
                LOGGER.info("Starting beacon attack...")
                scanner.send_beacon()
            elif action == "b.7":
                filename = input("Filename: ")
                scanner.save_scan(filename=
                                  filename if filename.endswith(".json") else filename + ".json"
                                    )
            elif action == "b.8":
                LOGGER.info("going back to start...")
                start = True
            elif action == "a.9" or action == "b.9":
                LOGGER.info("Exiting...")
                break
            else:
                print("Invalid input. Try again..")
                LOGGER.info("Invalid input detected")
            action = prompt_menu(start=start)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
