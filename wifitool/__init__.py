import logging
import os
import sys

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

