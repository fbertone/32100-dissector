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

## Contributing
Contributes of any kind are welcome.

Please report unknown types in order to increase the protocol's coverage
