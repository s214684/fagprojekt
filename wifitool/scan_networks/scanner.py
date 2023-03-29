import os
import time
from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff
from threading import Thread
import pandas
from subprocess import PIPE, run

from wifi import Wifi
from utils import get_current_channel


class Scanner:
    def __init__(self, interface: str):
        # self.APs: list = []
        self.clients: list = []
        self.wifis: list[Wifi] = []
        self.interface = interface
        self.curr_channel: int

    def __enter__(self):
        self.curr_channel = get_current_channel(iface=self.interface)
        os.system(f'ip link set dev {self.interface} down')
        os.system(f'iw dev {self.interface} set type monitor')
        os.system(f'ip link set dev {self.interface} up')
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        os.system(f'ip link set dev {self.interface} down')
        os.system(f'iw dev {self.interface} set type managed')
        os.system(f'ip link set dev {self.interface} up')

    def scan_network(self, interface: str, timeout: int = 20):
        """
        Scan the network and Populate variables
        """
        pass

    def _out(self, command) -> str:
        result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        return result.stdout

    def _get_current_channel(self, iface: str) -> str:
        x = self._out(f"iw {iface} info | grep 'channel' | cut -d ' ' -f 2")
        return x.strip()

    def _change_channel(self):
        """
        @ https://thepacketgeek.com/scapy/sniffing-custom-actions/part-2/
        Note: Channels 12 and 13 are allowed in low-power mode, while channel 14 is banned and only allowed in Japan.
        Thus we don't use channel 14.
        """
        ch = 1
        while True:
            os.system(f"iwconfig {self.interface} channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = (ch % 13) + 1
            time.sleep(0.5)  # TODO: Can we tune this?

    def set_channel(self, channel: int):
        # TODO ADD TRY STATEMENT AND CREATE EXCEPTION?
        os.system(f"iwconfig {self.interface} channel {channel}")
        self.curr_channel = channel

    def get_ap(self, timeout: int, specific_ap: str = "") -> pandas.DataFrame:


        def _callback(packet):
            if packet.haslayer(Dot11Beacon):
                # extract the MAC address of the network
                bssid = packet[Dot11].addr2
                packet[Dot11]
                # get the name of it
                ssid = packet[Dot11Elt].info.decode()
                if ssid in networks["SSID"].values or ssid.strip() == "":
                    return
                try:
                    dbm_signal = packet.dBm_AntSignal
                except Exception:
                    dbm_signal = "N/A"
                # extract network stats
                stats = packet[Dot11Beacon].network_stats()
                # get the channel of the AP
                channel = stats.get("channel")
                # get the crypto
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

                wifi = Wifi(ssid, bssid, dbm_signal, channel, crypto)
                if wifi not in self.wifis:
                    self.wifis.append(wifi)

        # initialize the networks dataframe that will contain all access points nearby
        networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        # set the index BSSID (MAC address of the AP)
        networks.set_index("BSSID", inplace=True)

        # start the channel changer
        channel_changer = Thread(target=self._change_channel)
        channel_changer.daemon = True
        channel_changer.start()

        if specific_ap:

            def _stopfilter(x) -> bool:
                if x[Dot11Elt].info.decode() == specific_ap:
                    print("Stopping sniff. Recieved:")
                    return True
                else:
                    return False

            sniff(prn=_callback, filter="type mgt subtype beacon", iface=self.interface, timeout=timeout, stop_filter=_stopfilter)
            # if specific_ap not in networks.SSID: #NOT WORKING
            #    raise ValueError
            return networks[(networks.SSID == specific_ap)]

        sniff(prn=_callback, filter="type mgt subtype beacon", iface=self.interface, timeout=timeout)

        return networks


    def get_clients(self, timeout: int) -> pandas.DataFrame:
        