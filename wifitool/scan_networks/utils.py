from getpass import getuser
from subprocess import PIPE, run
import logging
import os
import sys
import time


# Create the logger for the whole project
file_handler = logging.FileHandler(filename='wifitool.log')
file_handler.setLevel(level=logging.DEBUG)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers = [file_handler]

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s]-{%(filename)s:%(lineno)d} %(levelname)s: %(message)s',
    handlers=handlers  # type: ignore
)
LOGGER = logging.getLogger('wifitool')
LOGGER.debug("Logger created")


def out(command: str) -> str:
    """
    Small function to run shell commands
    Args:
        command: str - the command to execute
    """
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    return result.stdout


def set_interface_mode(interface: str, monitor_mode: bool) -> None:
    """
    Put network interface in monitor mode
    Args:
        interface: str - the interface in question
        monitor_mode: bool - True if interface should be in monitor mode
    """
    if monitor_mode:
        os.system(f'ip link set dev {interface} down')
        os.system(f'iw dev {interface} set type monitor')
        os.system(f'ip link set dev {interface} up')
    else:
        os.system(f'ip link set dev {interface} down')
        os.system(f'iw dev {interface} set type managed')
        os.system(f'ip link set dev {interface} up')


def check_system() -> str:
    """Checks if the user is root and if the system is Linux. If not, the program exits."""
    LOGGER.debug("Checking operating system")
    if sys.platform == "win32":
        LOGGER.debug("Windows detected")
        print("Windows detected")
        print("Windows users are at the moment not able to use this tool.")
        print("Please use a Linux distribution instead.")
        exit(1)
    LOGGER.debug("Checking if user is root")
    if sys.platform == "darwin":
        LOGGER.debug("MacOS detected")
        print("MacOS detected")
        print("MacOS users are at the moment not able to use this tool.")
        print("Please use a Linux distribution instead.")
        exit(1)
    if getuser() != "root":
        print("Error: You need to be root to run this script")
        LOGGER.debug("User is not root")
        exit(1)
    iface = get_iface().strip()
    if iface == "":
        LOGGER.debug("No wifi card detected")
        print("Error: No wifi card detected")
        exit(1)
    return iface


def get_current_channel(iface: str) -> str:
    """
    Get current channel

    Args:
        iface: str - Network interface to get current channel from
    Returns:
        str - current channel
    """
    x = out(f"iw {iface} info | grep 'channel' | cut -d ' ' -f 2")
    return x.strip()


def change_channel(interface: str) -> None:
    """
    Used to change the channel of inter interface
    Args:
        iface: str - Network interface to change channel
    Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
    Consequently we don't use channel 14.
    We change channel every 0.0205 seconds as this is optimal (see report if curious).
    """
    ch = 1
    while True:
        set_channel(interface, ch)
        ch = (ch % 13) + 1
        time.sleep(0.205)


def set_channel(interface: str, channel: int) -> None:
    """
    Sets channel of the network interface
    Args:
        interface: str - network interface
        channel: int - channel to switch to
    """
    try:
        os.system(f"iw dev {interface} set channel {channel}")
    except Exception:
        raise RuntimeError("Failed to set channel")

def strip_non_ascii(string: str) -> str:
    ''' Returns the string without non ASCII characters
    FROM: https://stackoverflow.com/questions/2743070/remove-non-ascii-characters-from-a-string-using-python-django
    '''
    s = string.encode('ascii',errors='ignore')
    return s.decode()

def get_iface() -> str:
    """
    Returns network interface of user system
    """
    return out("iw dev | grep Interface | cut -d ' ' -f 2").strip()
