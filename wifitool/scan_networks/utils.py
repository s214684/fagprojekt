import os

from subprocess import PIPE, run

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
