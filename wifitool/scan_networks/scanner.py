from deauth import deauth
from scapy.all import Dot11Beacon, Dot11, sniff, Dot11WEP, PcapWriter, RandMAC
from typing import Union
from threading import Thread
from utils import get_current_channel, change_channel, set_channel, strip_non_ascii, LOGGER, set_interface_mode
from wifi import Wifi
import json
import networkx as nx
import matplotlib.pyplot as plt
import time


class Scanner:
    """
    Context manager for scanning the network
    """
    def __init__(self, interface: str, timeout: int):
        LOGGER.debug("in init")
        self.wifis: list[Wifi] = []
        self.interface = interface
        self.curr_channel: int
        self.timeout: int = timeout

    def __enter__(self):
        """Enter the scanner context manager"""
        LOGGER.debug("Function '__enter__' is running")
        self.curr_channel = get_current_channel(iface=self.interface)
        # set the interface to monitor mode
        set_interface_mode(interface=self.interface, monitor_mode=True)
        LOGGER.debug("interface in monitor mode")
        # start the channel changer
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        LOGGER.info("Scanner entered")
        LOGGER.debug("out of __enter__")
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        """Exit the scanner context manager"""
        LOGGER.debug("Function '__exit__' is running")
        # Set the interface back to managed mode
        set_interface_mode(interface=self.interface, monitor_mode=False)
        # set the channel back to the original channel
        set_channel(self.interface, self.curr_channel)
        LOGGER.info("Exiting scanner")

    def create_json(self) -> dict:
        """
        Create JSON object of Scanner instance
        Returns:
            dict
        """
        # get the scan time
        LOGGER.info("Creating JSON object of Scanner instance")
        scan_time = time.time()

        # create the dictionary
        scan = {"Num_of_wifis": len(self.wifis),
                "scan_time": scan_time,
                "interface": self.interface,
                "TIMEOUT": self.timeout,
                "Topology": {}}  # the topology dictionary
        # for each wifi
        for wifi in self.wifis:
            # create the wifi dictionary
            wifi_dict = {"BSSID": wifi.BSSID,
                         "CRYPTO": wifi.crypto,
                         "CHANNEL": wifi.channel,
                         "DBM_SIGNAL": wifi.dBm_signal,
                         "COUNTRY": wifi.country,
                         "MAX_RATE": wifi.max_bitrate,
                         "BEACON_INTERVAL": wifi.beacon_interval,
                         "CLIENTS": wifi.clients}
            # add the wifi to the dictionary
            scan["Topology"][wifi.SSID] = wifi_dict
        return scan

    def save_scan(self) -> None:
        """Saves the topology to a file in JSON format:
        {Num_of_wifis: , scan_time: , interface: , TIMEOUT: , Topology: 
            {WIFI_NAME (SSID): 
                {BSSID: ,CRYPTO: , CHANNEL: , DBM_SIGNAL: , COUNTRY: , MAX_RATE: , BEACON_INTERVAL: , CLIENTS: [CLIENT_LIST]}}}
        """
        LOGGER.debug("Running 'save_scan' function")
        
        scan = self.create_json()

        # save the dictionary to the file
        with open("network_topology.json", "w") as file:
            json.dump(scan, file, indent=4)
        print(f"Network topology has been saved to file network_topology.json")
        LOGGER.info(f"Network scan has been saved to file")

    def png_scan(self) -> None:
        """
        Save the network topology as a graph in a png file
        """
        LOGGER.info("Creating a png of scanner instance")
        topology_json = self.create_json()

        # Create an empty graph
        graph = nx.Graph()
        
        # Add nodes to the graph
        for ssid, info in topology_json['Topology'].items():
            graph.add_node(ssid, label=ssid, is_client=False)
            for client in info['CLIENTS']:
                graph.add_node(client, label=client, is_client=True)
                graph.add_edge(ssid, client)

        # Set the positions of the nodes
        pos = nx.spring_layout(graph, k=1, iterations=50)

        # Draw access points
        nx.draw_networkx_nodes(graph, pos, nodelist=[node for node in graph.nodes if not graph.nodes[node]['is_client']], node_color='lightblue', node_size=300)

        # Draw clients
        nx.draw_networkx_nodes(graph, pos, nodelist=[node for node in graph.nodes if graph.nodes[node]['is_client']], node_color='red', node_size=100)

        # Draw edges
        nx.draw_networkx_edges(graph, pos)

        # Draw labels with adjusted positions to avoid overlap
        node_labels = nx.get_node_attributes(graph, 'label')
        label_pos = {node: (pos[node][0], pos[node][1] + 0.00) for node in graph.nodes}
        ap_labels = {node: label for node, label in node_labels.items() if not graph.nodes[node]['is_client']}
        nx.draw_networkx_labels(graph, label_pos, labels=ap_labels, font_color='black', font_size=8)

        # Set the font size for client labels
        client_labels = {node: label for node, label in node_labels.items() if graph.nodes[node]['is_client']}
        nx.draw_networkx_labels(graph, label_pos, labels=client_labels, font_color='black', font_size=5)

        # labels
        plt.legend(["AP", "client"])

        # Save the graph as a PNG file
        plt.savefig('network_topology.png', format='png', bbox_inches='tight', dpi=300)
        plt.clf()

    def scan(self, timeout: int = 0) -> None:
        """
        Scans the network for wifi networks and clients
        Args:
            timeout: int - The time to scan for
        """
        LOGGER.debug("Function 'scan' is running")
        if timeout == 0:
            timeout = self.timeout

        self.client_list: list[list[str]] = []

        def _callback(packet):
            # Check for type of packet
            if Dot11Beacon in packet.layers():
                wifi = self.handle_beacon(packet)
                if wifi not in self.wifis and wifi is Wifi:
                    self.wifis.append(wifi)
            elif packet[Dot11]:
                self.client_list = self.handle_clients(packet, self.client_list)

        LOGGER.info("Sniffing started")
        sniff(prn=_callback, iface=self.interface, timeout=timeout)

        for client in self.client_list:
            # find wifi that client communicated with
            for wifi in self.wifis:
                if wifi.BSSID == client[1]:
                    if client[0] not in wifi.clients:
                        wifi.clients.append(client[0])

    def handle_beacon(self, packet) -> Wifi:
        """
        Function to handle the beacon packets

        Args:
            packet: The packet sniffed

        Returns:
            Wifi: The wifi object created
        """
        # get the name of it
        stats = packet[Dot11Beacon].network_stats()
        try: 
            ssid = stats['ssid'].strip()
        except KeyError:
            return
        # check for hidden network
        if not ssid or ssid == "\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000":
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
        crypto = strip_non_ascii(str(stats["crypto"]))
        try:
            country = strip_non_ascii(stats['country'])
        except KeyError:
            country = ""
        max_rate = stats['rates'][-1]
        beacon_interval: int = packet[Dot11Beacon].fields['beacon_interval']

        return Wifi(ssid, bssid, dbm_signal, channel, crypto, max_rate, country, beacon_interval)

    def handle_clients(self, packet, client_list: list[list[str]]) -> list[list[str]]:
        """
        Function to handle the clients connected to the APs

        Args:
            packet : The packet sniffed
            client_list (list): The list of clients

        Returns:
            list: The list of clients
        """
        wifis_list_of_bssid = [wifi.BSSID for wifi in self.wifis]
        if self.from_client(packet):
            # extract the MAC address of the client
            src_BSSID = packet[Dot11].addr2
            if src_BSSID == "ff:ff:ff:ff:ff:ff":
                return client_list
            if packet[Dot11].addr1 in wifis_list_of_bssid:
                client_list.append([src_BSSID, packet[Dot11].addr1])
        else:
            # extract the MAC address of the Client
            dst_BSSID = packet[Dot11].addr1
            if dst_BSSID == "ff:ff:ff:ff:ff:ff":
                return client_list
            # check if source address is as specified
            if packet[Dot11].addr2 in wifis_list_of_bssid:
                client_list.append([dst_BSSID, packet[Dot11].addr2])
        return client_list

    def from_client(self, packet) -> bool:
        """Function to check whether the packet is sent from client or AP"""

        # extracting ds field from packet
        DS = packet.FCfield & 0x3
        to_ds = DS & 0x1 != 0
        from_ds = DS & 0x2 != 0

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
        LOGGER.debug("Function 'get_clients' is running")
        clients = []
        # Handle specific acces point specified
        if specific_acces_point:
            for wifi in self.wifis:
                if wifi.BSSID == specific_acces_point.BSSID:
                    # Add clients for specific AP to list
                    clients.append({"SSID": wifi.SSID, "clients": wifi.get_clients()})
                    return clients
            raise ValueError("The specific acces point was not found")
        else:
            # Add all clients to wifis
            for wifi in self.wifis:
                clients.append({"SSID": wifi.SSID, "clients": wifi.get_clients()})
        return clients if clients != [] else []

    def show_aps(self) -> bool:
        """for each AP print in tabular the data associated with it and its clients"""
        LOGGER.debug("Function 'show_aps' is running")
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
        LOGGER.debug("Function 'prompt_for_ap' is running")
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
        """Function to print the clients connected to the APs"""
        LOGGER.debug("Function 'show_clients' is running")
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
        """Function to send deauth packets to APs and clients"""
        LOGGER.debug("Function 'send_deauth' is running")
        if not self.wifis:
            print("AP list is empty, please scan the network first.")
            time.sleep(0.5)  # time for reading above print statement
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

    def get_ivs(self) -> None:
        """Function to get IVs from a chosen AP. Only APs with WEP encryption can be chosen"""
        LOGGER.debug("Function 'get_ivs' is running")
        if not self.wifis:
            print("AP list is empty, please scan the network first.")
            time.sleep(0.5)  # time for reading above print statement
            return

        # Create file to save IVs to
        pktdump = PcapWriter("iv_file.cap", append=True, sync=True)

        # Filter for WEP packets
        def filter_WEP(p):
            found = False
            if p.haslayer(Dot11WEP):
                if found == False:
                    found = True
                print("Found WEP packet")

                pktdump.write(p)

        # Get AP to sniff from
        target_ap = self.prompt_for_ap()
        
        if not target_ap.crypto == "{'WEP'}":
            print("AP is not WEP encrypted. Please choose another AP.")
            return
        
        set_channel(self.interface, target_ap.channel)
        
        time_for_sniff = input("How long do you want to capture IVs? (seconds): ")

        sniff(iface=self.interface, prn=filter_WEP, timeout=int(time_for_sniff))

        print(f'IVs saved to file: {pktdump.filename}.\n')
        LOGGER.info("IV captured :)")

    def crack_wep(self) -> None:
        """Function to crack WEP encryption"""
        LOGGER.debug("Function 'crack_wep' is running")
        print("Please run AirCrackNG ^.^")