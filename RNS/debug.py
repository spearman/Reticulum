from RNS import Packet

def show_packet(packet):
  print(f"PACKET ({len(packet.raw)} bytes):")
  print(f"  flags: {packet.raw[0]:08b}")
  print(f"  hops: {packet.raw[1]}")
  # exclude possibility of ifac for now
  assert not (packet.raw[0] & 0x80 == 0x80)
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
