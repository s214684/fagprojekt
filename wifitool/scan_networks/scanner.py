import os
import time
from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff, Dot11ProbeReq
from threading import Thread
import pandas
from getpass import getuser
from subprocess import PIPE, run

from client import Client
from wifi import Wifi
from utils import get_current_channel


class Scanner:
    """
    Context manager for scanning the network
    """
    def __init__(self, interface: str):
        # self.APs: list = []
        self.clients: list = []
        self.wifis: list[Wifi] = []
        self.interface = interface
        self.curr_channel: int

    def __enter__(self):
        if getuser() != "root":
            print("You need to be root to run this script")
            exit(1)
        self.curr_channel = get_current_channel(iface=self.interface)
        os.system(f'ip link set dev {self.interface} down')
        os.system(f'iw dev {self.interface} set type monitor')
        os.system(f'ip link set dev {self.interface} up')
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.set_channel(self.curr_channel)
        os.system(f'ip link set dev {self.interface} down')
        os.system(f'iw dev {self.interface} set type managed')
        os.system(f'ip link set dev {self.interface} up')

    def scan_network(self, interface: str, timeout: int = 20):
        """
        Scan the network and Populate variables
        TODO
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
            # os.system(f"iwconfig {self.interface} channel {ch}")
            os.system(f"iw dev {self.interface} set channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = (ch % 13) + 1
            time.sleep(0.5)  # TODO: Can we tune this?

    def set_channel(self, channel: int):
        # TODO ADD TRY STATEMENT AND CREATE EXCEPTION?
        # os.system(f"iwconfig {self.interface} channel {channel}")
        os.system(f"iw dev {self.interface} set channel {channel}")
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
            try:
                return networks[(networks.SSID == specific_ap)]
            except KeyError:
                return networks

        sniff(prn=_callback, filter="type mgt subtype beacon", iface=self.interface, timeout=timeout)
        return networks

    def get_clients_on_ap_probe(self, timeout: int) -> pandas.DataFrame:
        """
        Read probe requests and populate clients list
        The probe request is used to find the MAC address of the client as it is only clients that send probe requests
        """
        def _callback(packet):
            if packet.haslayer(Dot11ProbeReq):
                # extract the MAC address of the network
                MAC = packet[Dot11].addr2
                if MAC in clients["MAC"].values:
                    return
                try:
                    RSSI = packet.dBm_AntSignal
                except Exception:
                    RSSI = "N/A"
                clients.loc[MAC] = (MAC, RSSI)
                client = Client(MAC, RSSI)
                if client not in self.clients:
                    self.clients.append(client)

        clients = pandas.DataFrame(columns=["MAC", "RSSI"])
        # set the index BSSID (MAC address of the AP)
        clients.set_index("MAC", inplace=True)
        sniff(prn=_callback, filter="type mgt subtype probe-req", iface=self.interface, timeout=timeout)

    def get_clients_on_ap(self, timeout: int, iface: str, dst_BSSID: str) -> list[str]:
        """Function to create a list of the clients communicating with a certain AP

        Args:
            timeout (int): Time to run sniff
            iface (str): Interface to sniff
            dst_BSSID (str): AP from which clients will be listed

        Returns:
            list: List of unique clients that are connected to the AP specified
        """
        # find wifi with dst_bssid from self.wifis
        wifi = None
        for w in self.wifis:
            if w.BSSID == dst_BSSID:
                wifi = w
                break
        if wifi is None:
            raise ValueError("Could not find wifi with specified BSSID")

        client_list = []

        def _is_packet_from_client(packet) -> bool:
            """Function to check whether the packet is sent from client or AP"""

            DS = packet.FCfield & 0x3
            to_ds = DS & 0x1 != 0
            from_ds = DS & 0x2 != 0

            # to_ds betyder at addr1 vil være AP, og addr2 vil være client.

            if not to_ds and from_ds:
                # Packet is sent from AP to client
                return False
            elif to_ds and not from_ds:
                # Packet is sent from client to AP
                return True
            else:
                # Invalid configuration (e.g., ad-hoc mode)
                return False

        def _callback(packet) -> None:
            """Checks conditions, and adds clients to list"""

            if packet.haslayer(Dot11):

                if _is_packet_from_client(packet):  # type: ignore[truthy-function]
                    # extract the MAC address of the client
                    src_BSSID = packet[Dot11].addr2
                    # check if destination address is as specified
                    if packet[Dot11].addr1 == dst_BSSID:
                        client_list.append(src_BSSID)

        sniff(timeout=timeout, iface=iface, prn=_callback)

        if client_list == []:
            print("Found no clients, trying again...")
            sniff(timeout=timeout, iface=iface, prn=_callback)

        print("Finished scanning")
        # Add clients to wifi object if they are not already there
        for client in client_list:
            if client not in wifi.clients:
                wifi.clients.append(client)
        return list(set(client_list))

    def get_clients(self, timeout: int) -> list[str]:
        """Function to populate the clients list of each AP

        Args:
            timeout (int): Time to run sniff

        Returns:
            list: List of unique clients that are connected to the AP specified
        """
        client_list = []
        wifis_list_of_bssid = [wifi.BSSID for wifi in self.wifis]

        def _is_packet_from_client(packet) -> bool:
            """Function to check whether the packet is sent from client or AP"""

            DS = packet.FCfield & 0x3
            to_ds = DS & 0x1 != 0
            from_ds = DS & 0x2 != 0

            # to_ds betyder at addr1 vil være AP, og addr2 vil være client.

            if not to_ds and from_ds:
                # Packet is sent from AP to client
                return False
            elif to_ds and not from_ds:
                # Packet is sent from client to AP
                return True
            else:
                # Invalid configuration (e.g., ad-hoc mode)
                return False

        def _callback(packet) -> None:
            """Checks conditions, and adds clients to list"""

            if packet.haslayer(Dot11):

                if _is_packet_from_client(packet):  # type: ignore[truthy-function]
                    # extract the MAC address of the client
                    src_BSSID = packet[Dot11].addr2
                    # check if destination address is as specified
                    if packet[Dot11].addr1 in wifis_list_of_bssid:
                        client_list.append([src_BSSID, packet[Dot11].addr1])

        sniff(timeout=timeout, iface=self.interface, prn=_callback)

        if client_list == []:
            print("Found no clients, trying again...")
            sniff(timeout=timeout, iface=self.interface, prn=_callback)

        print("Finished scanning")
        # Add clients to wifi if they communicated with wifi and are not already there
        for client in client_list:
            # find wifi that client communicated with
            for wifi in self.wifis:
                if wifi.BSSID == client[1]:
                    if client[0] not in wifi.clients:
                        wifi.clients.append(client[0])
        return list(set(client_list[0]))
