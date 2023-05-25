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
