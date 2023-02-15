# Project description



## Product brainstorm


### General:
new:
- Rouge access point
- Four-Way-Handshake
- Deauthentication attack
- Password cracking
- Man in the middle
---
old:
- RaspberryPi Pineapple, "WiFi swiss army knife".
- Scapy library to be used
- Man in the middle.
- Checks the wifis in the area, and displays them with multiple functionalities.
- Sniff all wireless traffic.
- Recognise difference between traffic types:
    probe messages, 4-way-handshakes, 


### Required functionalities:
- Listening for wireless data.
- Identifying sendes and recieveres of said data
- Scanning for routers and AP's in the area.
- Gaining access to network card, read from it and send to it. (windows and macOS complications??)


### Possible extra functionalities:
- Tracking people in the area(recognises mac addresse, and how long they have been known).
- FHSS(see which band is used).
- Distance from user to pruduct (triangulation).
- Implement a 4-way-handshake.
    able to connect to an AP.
    Possible using an existing library.
- Reinstallation attack.
- Password cracking.
- Encryption/Decryption (possibly out of the scope of the project).
- Deauthenticating users.

---

## Actual description

The product of this project is a Pineapple clone. We will create a rouge access point, that will appear with the name of an existing AP in the vicinity. We will then have the possibility of a deauthentication attack, thus disconnecting a user from the AP we are pretending to be. The user should then connect to our AP instead, in the belief that our AP is the one he/she was connected to earlier. Thereby functioning as a man in the middle, and having the ability to see, and or change, the requests and replies sent by/to the user. In order to see/change information from/to the user, we will need to implement a four-way-handshake as well. An additional functionality that could possibly be implemented is password cracking, in order to get the password for the AP. Although this will be of lower priority than rouge AP, de-auth'ing four-way-handshake and acting as man in the middle.







