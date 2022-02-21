package main

func IsGameInfoPacket(payload []uint8, srcPort uint16) bool {
	if len(payload) < 24 {
		return false
	}
	if payload[0] == 0xf7 && payload[1] == 0x30 {
		port := uint16(payload[len(payload)-1]<<8) | uint16(payload[len(payload)-2])
		if port == srcPort {
			return true
		}
	}
	return false
}

func RewriteGameInfoPacket(payload *[]uint8, newSrcPort uint16) {
	if len(*payload) < 2 {
		return
	}
	(*payload)[len(*payload)-1] = uint8(newSrcPort >> 8 & 0x00ff)
	(*payload)[len(*payload)-2] = uint8(newSrcPort & 0x00ff)
}
