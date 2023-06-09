import logging
import os
import sys
import time

# TODO: Is this logger needed? (When we have the logger in the utils file)
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

# TODO: Is this needed?
def test_interface(interface):
    pass

# TODO: Is this needed?
def setup_interface(interface):
    pass

# TODO: This exists in util and scanner already, remove?
def set_interface_to_monitor_mode(interface):
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' monitor')
    os.system('ifconfig ' + interface + ' up')

# TODO: Seems unnecessary, remove?
def get_interface_info():
    return "interface info"

# TODO: Seems unnecessary, remove?
def print_all(stuff_to_print):
    """
    @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
    """
    while True:
        os.system("clear")
        print(stuff_to_print)
        time.sleep(0.5)

# TODO: Exists in scanner, unused, remove?
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
