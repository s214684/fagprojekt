from scanner import Scanner


with Scanner("wlan0", 5) as scanner:
    scanner.test()
