from threading import Lock
from RNS import Destination, Packet, Transport

debug_lock = Lock()

def show_packet_type(packet_type) -> str:
  match packet_type:
    case Packet.DATA:
      return "DATA"
    case Packet.ANNOUNCE:
      return "ANNOUNCE"
    case Packet.LINKREQUEST:
      return "LINKREQUEST"
    case Packet.PROOF:
      return "PROOF"
    case _:
      assert False

def show_packet_context(packet_context) -> str:
  match packet_context:
    case Packet.NONE:
      return "NONE"
    case Packet.RESOURCE:
      return "RESOURCE"
    case Packet.RESOURCE_ADV:
      return "RESOURCE_ADV"
    case Packet.RESOURCE_REQ:
      return "RESOURCE_REQ"
    case Packet.RESOURCE_HMU:
      return "RESOURCE_HMU"
    case Packet.RESOURCE_PRF:
      return "RESOURCE_PRF"
    case Packet.RESOURCE_ICL:
      return "RESOURCE_ICL"
    case Packet.RESOURCE_RCL:
      return "RESOURCE_RCL"
    case Packet.CACHE_REQUEST:
      return "CACHE_REQUEST"
    case Packet.REQUEST:
      return "REQUEST"
    case Packet.RESPONSE:
      return "RESPONSE"
    case Packet.PATH_RESPONSE:
      return "PATH_RESPONSE"
    case Packet.COMMAND:
      return "COMMAND"
    case Packet.COMMAND_STATUS:
      return "COMMAND_STATUS"
    case Packet.CHANNEL:
      return "CHANNEL"
    case Packet.KEEPALIVE:
      return "KEEPALIVE"
    case Packet.LINKIDENTIFY:
      return "LINKIDENTIFY"
    case Packet.LINKCLOSE:
      return "LINKCLOSE"
    case Packet.LINKPROOF:
      return "LINKPROOF"
    case Packet.LRRTT:
      return "LRRTT"
    case Packet.LRPROOF:
      return "LRPROOF"
    case _:
      assert False

def show_transport_type(transport_type) -> str:
  match transport_type:
    case Transport.BROADCAST:
      return "BROADCAST"
    case Transport.TRANSPORT:
      return "TRANSPORT"
    case Transport.RELAY:
      return "RELAY"
    case Transport.TUNNEL:
      return "TUNNEL"
    case _:
      assert False

def show_destination_type(destination_type) -> str:
  match destination_type:
    case Destination.SINGLE:
      return "SINGLE"
    case Destination.GROUP:
      return "GROUP"
    case Destination.PLAIN:
      return "PLAIN"
    case Destination.LINK:
      return "LINK"
    case _:
      assert False

def show_packet(packet):
  #print("-----------------------------------------------------------------------------------")
  packet_type = show_packet_type(packet.packet_type)
  packet_context = show_packet_context(packet.context)
  transport_type = show_transport_type(packet.transport_type)
  # NOTE: destination_type field may not be set if packet is not unpacked?
  destination_type = (packet.flags & 0b00001100) >> 2
  destination_type = show_destination_type(destination_type)
  print(f"PACKET {packet_type}[{packet_context}][{transport_type}][{destination_type}]"
    f" ({len(packet.raw)} bytes):")
  print(f"  flags: {packet.raw[0]:08b}")
  print(f"  hops: {packet.raw[1]}")
  # exclude possibility of ifac for now
  assert packet.raw[0] & 0x80 != 0x80
  print(f"  address: {bytes(packet.raw[2:18]).hex()}")
  b = 18
  if packet.header_type == Packet.HEADER_2:
    print(f"  address2: {bytes(packet.raw[18:34]).hex()}")
    b = 34
  print(f"  context: {packet.raw[b]}")
  b += 1
  print(f"  data: {len(packet.raw[b:])} bytes")
  print("  ---")
  if packet.packet_type == Packet.ANNOUNCE:
    print(f"  pubkey: {bytes(packet.raw[b:b+32]).hex()}")
    b += 32
    print(f"  verifykey: {bytes(packet.raw[b:b+32]).hex()}")
    b += 32
    print(f"  name hash: {bytes(packet.raw[b:b+10]).hex()}")
    b += 10
    print(f"  random hash: {bytes(packet.raw[b:b+10]).hex()}")
    b += 10
    print(f"  signature: {bytes(packet.raw[b:b+64]).hex()}")
    b += 64
    print(f"  application data: {len(packet.raw[b:])} bytes")
  elif packet.packet_type == Packet.LINKREQUEST:
    print(f"  pubkey: {bytes(packet.raw[b:b+32]).hex()}")
    b += 32
    print(f"  verifykey: {bytes(packet.raw[b:b+32]).hex()}")
    b += 32
  print("-----------------------------------------------------------------------------------")

def get_announce_random_blob(packet):
  if packet.packet_type == Packet.ANNOUNCE:
    b = 18
    if packet.header_type == Packet.HEADER_2:
      b = 34
    b += 1
    b += 32
    b += 32
    b += 10
    return bytes(packet.raw[b:b+10]).hex()
