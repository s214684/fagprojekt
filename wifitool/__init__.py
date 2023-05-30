import logging
import os
import sys
import time

file_handler = logging.FileHandler(filename='tmp.log')
file_handler.setLevel(level=logging.DEBUG)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers = [file_handler, stdout_handler]

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s]-{%(filename)s:%(lineno)d} %(levelname)s: %(message)s',
    handlers=handlers  # type: ignore
)
LOGGER = logging.getLogger('wifitool')
LOGGER.debug("Logger created")


def test_interface(interface):
    pass


def setup_interface(interface):
    pass


def set_interface_to_monitor_mode(interface):

    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' monitor')
    os.system('ifconfig ' + interface + ' up')


def get_interface_info():
    return "interface info"


def print_all(stuff_to_print):
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    """
    while True:
        os.system("clear")
        print(stuff_to_print)
        time.sleep(0.5)


def change_channel(interface: str):
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
    Thus we don't use channel 14.
    """
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = (ch % 13) + 1
        time.sleep(0.5)
