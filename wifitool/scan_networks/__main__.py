from cli import prompt_menu, options_menu, start_menu
from scanner import Scanner
from utils import check_system
from utils import LOGGER
import sys


def main(interface: str, timeout: int) -> None:
    """Main function of the program."""
    with Scanner(interface, timeout) as scanner:
        """The context manager is entered here. Then the functions are called based on the user input."""
        scanner = scanner
        LOGGER.info("Starting WifiTool...")
        # Clear screen
        print("\033c")
        try:
            start_menu(scanner)
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)


if __name__ == "__main__":
    INTERFACE = check_system()
    TIMEOUT = 20
    main(INTERFACE, TIMEOUT)
