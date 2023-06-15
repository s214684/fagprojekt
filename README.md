# WiFi-scanning, Deauthentication and Password cracking

This program allows the user to scan local networks for APs and clients and shows information about these. It also has a tool for doing deauthentication attacks and cracking WEP protected APs. These functions work in conjunction to create a complete tool with a CLI based UI. It can also display information as both a .json file or a .png file. 

## User guide:
Run the program in linux as sudo.

First a menu is shown where the user has 3 options. Either choose options by inputting 3 or do a scan to obtain the network topology. You cannot do a WEP scan without obtaining the topology first.

Once you have done a scan, then you have several choices. You can scan the networks again, show APs or clients, send deauth or save the network topology as a .json or .png.

Scanning the network again, scans for topology again. Showing Aps shows SSID, BSSID, the channel, cryptography, the country, max bitrate and the beacon interval. Showing clients makes you choose an AP and shows which clients with their BSSID are connected to that specific AP.

Choosing the deauth option gives you a menu to choose which AP to deauth and which clients on that specific AP to deauth or deauth all clients connected. The deauth attack is stopped by a keyboard interrupt and will continue to interrupt the client or AP for as long as the program is running. The keyboard interrupt will not stop the entire program but return to the menu.

Then you can get the network topology saved as either a .json file or a .png, where all APs and their connected clients are shown, by their BSSID.

Back at the main menu you can now choose the Crack WEP option. In this menu you can choose between choosing an AP to scan or cracking their WEP. Choosing an AP to scan shows all local APs and allows you to choose which AP to scan, only choose WEP networks as that is what our program works with. Then choose how long you want to scan, it will tell you if the scan works as it will warn you when the first WEP packet is found. 

Then you can choose to crack that AP, but it will just tell you to use Aircrack. Do that by installing aircrack-ng on linux and then running a terminal where the file iv_file.cap is located and running the command: "sudo aircrack-ng iv_file.cap" and it should crack the WiFi.

From the main menu, you can go to the options menu. Here you can choose between the timeout, which is for how long it should scan for beacon frames to get the network topology. The default is 7 seconds, which should be enough to get all APs and most clients if they are active on the network. If not, you can set a longer timeout. You can also choose another interface in case you have multiple interfaces set up. This is only recommended for advanced users as the default should work.


