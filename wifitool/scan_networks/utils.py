from getpass import getuser
from scapy.all import sniff
from subprocess import PIPE, run
import logging
import os
import sys
import time


# Create the logger for the whole project
file_handler = logging.FileHandler(filename='log.log')
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


def out(command) -> str:
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    return result.stdout


def set_interface_to_monitor_mode(interface):
    os.system(f'ip link set dev {interface} down')
    os.system(f'iw dev {interface} set type monitor')
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
    x = out(f"iw {iface} info | grep 'channel' | cut -d ' ' -f 2")
    return x.strip()


def change_channel() -> None:
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
    Thus we don't use channel 14.
    """
    ch = 1
    interface = get_iface()
    while True:
        set_channel(interface, ch)
        # switch channel from 1 to 14 each 0.5s
        ch = (ch % 13) + 1
        time.sleep(0.205)  # TODO: Can we tune this?


def set_channel(interface, channel: int) -> None:
    try:
        os.system(f"iw dev {interface} set channel {channel}")
    except Exception:
        print("Failed to set channel")

def strip_non_ascii(string: str) -> str:
    ''' Returns the string without non ASCII characters
    FROM: https://stackoverflow.com/questions/2743070/remove-non-ascii-characters-from-a-string-using-python-django
    '''
    s = string.encode('ascii',errors='ignore')
    return s.decode()

def get_iface() -> str:
    return out("iw dev | grep Interface | cut -d ' ' -f 2").strip()


def sniff_5_packets(iface: str):
    return sniff(count=5, filter="type mgt", iface=iface)
