import os
import time
from typing import Union
from scapy.all import Dot11Beacon, Dot11, Dot11Elt, sniff, Dot11ProbeReq, Dot11ProbeResp
from threading import Thread
import pandas
from subprocess import PIPE, run
from deauth import deauth
from wifi import Wifi
from utils import get_current_channel, change_channel


class Scanner:
    """
    Context manager for scanning the network
    """
    def __init__(self, interface: str, timeout):
        self.wifis: list[Wifi] = []
        self.interface = interface
        self.curr_channel: int
        self.timeout: int = timeout

    def __enter__(self):
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

    def _out(self, command) -> str:
        result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        return result.stdout

    def scan_for_aps(self, timeout: int = 0, specific_ap: str = "") -> pandas.DataFrame:
        if timeout == 0:
            timeout = self.timeout

        def _callback(packet):
            if packet.haslayer(Dot11Beacon):
                # extract the MAC address of the network
                bssid = packet[Dot11].addr2
                packet[Dot11]
                # get the name of it
                ssid = packet[Dot11Elt].info.decode()
                if not packet.info:
                    ssid = "'Hidden SSID'"
                if ssid in networks["SSID"].values:
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
        channel_changer = Thread(target=change_channel)
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
        change_channel.stop()
        return networks

    def scan_for_clients(self, timeout: int = 0) -> list[str]:
        """Function to populate the clients list of each AP

        Args:
            timeout (int): Time to run sniff

        Returns:
            list: List of unique clients that are connected to the AP specified
        """

        if timeout == 0:
            timeout = self.timeout

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
                else:
                    # extract the MAC address of the Client
                    dst_BSSID = packet[Dot11].addr1
                    # check if source address is as specified
                    if packet[Dot11].addr2 in wifis_list_of_bssid:
                        client_list.append([dst_BSSID, packet[Dot11].addr2])

        # start the channel changer
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()

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
        channel_changer.stop()
        return list(set(client_list[0])) if client_list != [] else []

    def scan_network(self) -> bool:
        print("Scanning network for APs...")
        AP_info = self.scan_for_aps()
        print(AP_info)

        # scan network for clients as well
        print("Scanning network for clients...")
        self.scan_for_clients()
        # for each AP print the clients
        for wifi in self.wifis:
            print(f"{wifi.SSID} - {wifi.BSSID} - {wifi.get_clients_MAC()}")

        return True

    def show_aps(self):
        # Check if we have scanned the network. If so, show APs from scanner.wifis
        if self.wifis:
            # Print APs in a nice way
            for i, wifi in enumerate(self.wifis):
                print(f"{i}. {wifi.SSID} - {wifi.BSSID}")

            # Prompt user if they want more info on AP
            more_info = input("Do you want more info on AP? (y/n): ").strip()
            if more_info == "y":
                AP_to_show = int(input("Input index of AP to show: "))
                print(self.wifis[AP_to_show].details())

        else:
            print("No APs found. Try scanning network first.")
            return False

    def prompt_for_ap(self) -> Wifi:
        """
        Check if we have scanned the network. If so, we can prompt user for AP to attack from scanner.wifis
        Then in scanner.wifis find the AP with the same BSSID as the one we scanned for
        Then check if we found the AP
        """
        def _get_targeted_ap() -> Wifi:
            AP_to_attack_str = input("Input AP BSSID for client scan: ")
            print("Scanning network for selected AP...")
            self.scan_for_aps(specific_ap=AP_to_attack_str)
            # in scanner.wifis find the AP with the same BSSID as the one we scanned for
            for wifi in self.wifis:
                if wifi.BSSID == AP_to_attack_str:
                    target_ap = wifi
                    break
            # check if we found the AP
            if not target_ap:
                print("Could not find AP in scanned APs. Try scanning network first.")
                return False
            return target_ap

        if self.wifis:
            print("Choose AP from list: ")
            for i, wifi in enumerate(self.wifis):
                print(f"{i}. {wifi.SSID} - {wifi.BSSID}")
            print(f"{len(self.wifis)+1}. User defined AP")
            AP_to_attack = int(input("Input index of AP to attack: "))
            if AP_to_attack == len(self.wifis) + 1:
                target_ap = _get_targeted_ap()
            target_ap = self.wifis[AP_to_attack]
        else:
            print("No APs found. Try scanning network first.")
            return False
        return target_ap

    def show_clients(self) -> bool:
        target_ap = self.prompt_for_ap()
        print(f"Extracting client list for AP: {target_ap.SSID}")
        # Get clients from AP
        if target_ap.clients:
            print("Clients on AP:")
            print(target_ap.get_clients_MAC())
        else:
            print("No clients found on AP.")
            # prompt if user wants to seach for clients on AP
            search_for_clients = input("Do you want to search for clients on AP? (y/n): ").strip()
            if search_for_clients == "y":
                self.scan_for_clients()
        return True

    def send_deauth(self):
        target_ap = self.prompt_for_ap()
        self.set_channel(target_ap.channel)

        # Check if we have clients on the AP. If so, prompt user for client to deauth
        if target_ap.clients:
            print("Choose client to deauth from list:")
            for i, client in enumerate(target_ap.clients):
                print(f"{i}. {client}")
            print(f"{len(target_ap.clients)+1}. User defined client")
            print(f"{len(target_ap.clients)+2}. Deauth all clients")
            client_to_deauth = int(input("Input choice: "))

            if client_to_deauth == len(target_ap.clients) + 1:
                target_client = input("Input client MAC for deauth: ")
            elif client_to_deauth == len(target_ap.clients) + 2:
                target_client = "ff:ff:ff:ff:ff:ff"
            else:
                target_client = target_ap.clients[client_to_deauth]

        # If we don't have clients on the AP, prompt user for client to deauth
        else:
            target_client = input("Input client MAC for deauth: ")

        deauth(self.interface, target_ap.BSSID, target_client)
