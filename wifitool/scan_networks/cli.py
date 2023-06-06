import datetime
from scanner import Scanner


# Terminal menu for user to choose what to do
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
    4. Send deauth with beacon
    5. Crack WEP

    8. Back to start
    9. Exit (Ctrl+C)

    """

    print(string_to_show)

    action = input("Input action wanted: ").strip()
    action = "a." + action if start else "b." + action
    print("\033c")

    return action


def options(scanner: Scanner) -> None:
    # Let user set constants such as timeout and interface
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
        options(scanner)
    elif choice == "2":
        interface = input("Input new interface: ")
        scanner.interface = interface
        options(scanner)
    elif choice == "3":
        return
    else:
        print("Invalid input. Try again..")
        options(scanner)
