import os
import logging
from subprocess import PIPE, run
from scapy.all import sniff


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

def out(command) -> str:
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    return result.stdout


def set_interface_to_monitor_mode(interface):

    os.system(f'ip link set dev {interface} down')
    os.system(f'iw dev {interface} set type monitor')
    os.system(f'ip link set dev {interface} up')


def set_channel(interface: str, channel: str) -> None:
    out(f"iw dev {interface} set channel {channel}")


def get_current_channel(iface: str) -> str:
    x = out(f"iw {iface} info | grep 'channel' | cut -d ' ' -f 2")
    return x.strip()


def sniff_5_packets(iface: str):
    return sniff(count=5, filter="type mgt", iface=iface)
