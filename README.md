# 32100-dissector
Wireshark dissector useful to analyze [32100 UDP protocol](https://github.com/fbertone/lib32100/wiki)

## Install
Copy 32100_dissector.lua in Wireshark's plugin directory (try subdirectories like wireshark or <version> if it doesn't work on plugins root)

Alternatively run run Wireshark from command line like this:

```bash
wireshark -X lua_script:32100_dissector.lua
```

## Usage
The dissector should automatically handle packets sent to or from UDP port 32100

![dissected packet](https://github.com/fbertone/32100-dissector/raw/master/images/snap1.jpeg "Example of dissected packet")

You can use filters like
* `32100` to display only protocol's packet or
* `32100.known == false` to check messages still not known
* `32100.type == 0x20` to only show specific type of messages

Since the communication between devices and apps (and relay servers) goes through other ports than 32100, the packet dissection is not handled automatically.

However, you can force Wireshark to dissect them by manually selecting the protocol.

1. Right-click on a packet and select `Decode as...`
![Decode as menu](https://github.com/fbertone/32100-dissector/raw/master/images/decode_as1.jpg "Right-click and select Decode as...")

2. In `current` drop-down menu pick `32100`
![Current dropdown menu](https://github.com/fbertone/32100-dissector/raw/master/images/decode_as2.jpg "In current menu choose 32100")

3. All packets exchanged through the same port are now interpreted as 32100 protocol. Repeat with all missing packets on different ports.
![Packets interpreted as 32100](https://github.com/fbertone/32100-dissector/raw/master/images/decode_as3.jpg "Packets are now interpreted as 32100 protocol")

## Contributing
Contributes of any kind are welcome.

Please report unknown types in order to increase the protocol's coverage
