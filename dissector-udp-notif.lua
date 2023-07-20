-- Wireshark UDP-Notif dissector

-- todo:
--   handle options
--   handle segmentation

un_prot = Proto("udpnotif", "UDP-Notif")

local f_ver = ProtoField.uint8("udpnotif.version", "Version", base.DEC)
local f_enc = ProtoField.uint8("udpnotif.encoding", "Encoding", base.DEC)
local f_hdr_len = ProtoField.uint8("udpnotif.hdr_len", "Header Length", base.DEC)
local f_msg_len = ProtoField.uint16("udpnotif.msg_len", "Message Length", base.DEC)
local f_obs_dom = ProtoField.uint32("udpnotif.obs_dom", "Observation Domain ID", base.DEC)
local f_msg_id = ProtoField.uint32("udpnotif.msg_id", "Message ID", base.DEC)
local f_options = ProtoField.uint32("udpnotif.options", "Options", base.DEC)

un_prot.fields = { f_ver, f_enc, f_hdr_len, f_msg_len, f_obs_dom, f_msg_id, f_options }

function un_prot.dissector(buf, pkt, tree)
  if buf:len() < 12 then return end

  pkt.cols.protocol = un_prot.name
  local subtree = tree:add(un_prot, buf(), "UDP-Notif Protocol")
  local version = buf(0,1):uint() / 32
  subtree:add(f_ver, buf(0,1), version)
  local enc = buf(0,1):uint() % 16
  local enc_cust = buf(0,1):uint() / 16 % 2
  local enc_name = "unknown"
  if enc_cust == 1 then enc_name = "custom"
  else
    if enc == 1 then enc_name = "application/yang-data+json"
    elseif enc == 2 then enc_name = "application/yang-data+xml"
    elseif enc == 3 then enc_name = "application/yang-data+cbor"
    end
  end
  subtree:add(f_enc, buf(0,1), enc):append_text(" (" .. enc_name .. ")")
  subtree:add(f_hdr_len, buf(1,1))
  subtree:add(f_msg_len, buf(2,2))
  subtree:add(f_obs_dom, buf(4,4))
  subtree:add(f_msg_id, buf(8,4))
  local data_dis = Dissector.get("data")
  local hdr_len = buf(1,1):uint()
  -- work around some strange version 0 implementations
  if version == 0 and hdr_len < 12 then hdr_len = 12 end
  data_dis:call(buf(hdr_len):tvb(), pkt, tree)
end

DissectorTable.get("udp.port"):add(0, un_prot)
