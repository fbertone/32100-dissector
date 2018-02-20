-- Wireshark dissector for IoT protocol running on UDP port 32100
-- Author: Fabrizio Bertone <fab.bertone@gmail.com>
-- Version: 0.0.2 (2018-02-18_1)
-- https://github.com/fbertone/32100-dissector

-- known message types
messages = {
  [0xf100] = "STUN request",
  [0xf101] = "STUN response",
  [0xf102] = "Send ping to server ???",
  [0xf103] = "TURN NACK / server ping ???",
  [0xf110] = "UID register (cam online) ???",
  [0xf111] = "UID register Response ???",
  [0xf120] = "UID Lookup Request 1",
  [0xf121] = "UID Lookup ACK",
  [0xf130] = "Hello World ???",
  [0xf140] = "UID Lookup Response 1",
  [0xf141] = "UID Session Open Request",
  [0xf142] = "UID Session Open Response",
  [0xf167] = "UID Lookup Request 2",
  [0xf169] = "UID Lookup Response 2 (TURN servers list)",
  [0xf170] = "TURN server init (C->S)",
  [0xf171] = "TURN server OK (S->C)",
  [0xf172] = "TURN server OK2 (C->S)",
  [0xf173] = "TURN server password ???",
  [0xf180] = "TURN server UID lookup request ???",
  [0xf182] = "TURN server redirect ???",
  [0xf183] = "TURN server UID lookup request 2 (connection) ???",
  [0xf184] = "TURN server UID lookup response 2 (connecting...) ???",
  [0xf191] = "UID de-register (reboot) ???",
  [0xf1d0] = "Data",
  [0xf1d1] = "Data ACK",
  [0xf1e0] = "PING",
  [0xf1e1] = "PONG",
  [0xf1f0] = "Session END",
}

-- declare our protocol
IoT32100_proto = Proto("32100","32100 IoT Protocol")

-- declare fields
local F_fullnumtype = ProtoField.new("Full Numeric Type", "32100.fulltype", ftypes.UINT16, nil, base.DEC_HEX, nil, "Full Message Type (DEC_HEX)")
local F_numtype = ProtoField.new("Numeric Type", "32100.type", ftypes.UINT8, nil, base.DEC_HEX, nil, "Short Message Type (DEC_HEX)")
local F_strtype = ProtoField.new("Description", "32100.description", ftypes.STRING, nil, nil, nil, "Message Type Description (STRING)")
local F_known = ProtoField.new("Known type", "32100.known", ftypes.BOOLEAN, nil, nil, nil, "Message type is known (BOOLEAN)")
local F_paylen = ProtoField.new("Payload length", "32100.paylen", ftypes.UINT16, nil, base.DEC, nil, "Payload Length (DEC)")

-- add the fields to the protocol
-- (to confirm this worked, check that these fields appeared in the "Filter Expression" dialog)
IoT32100_proto.fields = {F_fullnumtype, F_numtype, F_strtype, F_known, F_paylen}

-- create a function to dissect it
function IoT32100_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "32100"
    local full_type = buffer(0,2):uint()
    local num_type = buffer(1,1):uint()
    local known = false
    local str_type = "Unknown - " .. string.format("0x%x", full_type)

    if (messages[full_type]) then
      known = true
      str_type = messages[full_type]
    end

    local payload_len = buffer(2,2):uint()
    local payload = buffer(4,payload_len)

    local subtree = tree:add(IoT32100_proto,buffer(),"32100 Protocol")

    subtree:add(F_fullnumtype, buffer(0,2), full_type)
    subtree:add(F_numtype, buffer(1,1), num_type)
    subtree:add(F_strtype, buffer(0,2), str_type)
    subtree:add(F_known, buffer(0,2), known)
    subtree:add(F_paylen, buffer(2,2), payload_len)

end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 32100
udp_table:add(32100,IoT32100_proto)
