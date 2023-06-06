from scanner import Scanner
from utils import check_system
import sys
from cli import prompt_menu, options

INTERFACE = check_system()
TIMEOUT = 20

with Scanner(INTERFACE, TIMEOUT) as scanner:
    scanner = scanner
    # Clear screen
    print("\033c")
    start = True
    try:
        action = prompt_menu(welcome=True, start=True)
        while True:
            # Clear screen
            start = False
            if action == "a.1":
                scanner.scan_network()
            elif action == "a.2" or action == "b.2":
                scanner.show_clients()
            elif action == "b.1":
                scanner.show_aps()
            elif action == "b.3":
                scanner.send_deauth()
            elif action == "a.3":
                options(scanner)
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
