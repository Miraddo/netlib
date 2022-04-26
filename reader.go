// Package tcp
package tcp

import "encoding/binary"

func (p Packet) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p[0:])
}

func (p Packet) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p Packet) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(p[4:])
}

func (p Packet) AckNumber() uint32 {
	return binary.BigEndian.Uint32(p[8:])
}

func (p Packet) DataOffset() uint8 {
	return (p[12] >> 4) * 4
}

func (p Packet) Window() uint16 {
	return binary.BigEndian.Uint16(p[14:])
}

func (p Packet) GetChecksum() uint16 {
	return binary.BigEndian.Uint16(p[16:])
}

func (p Packet) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(p[18:])
}

func (p Packet) Options() []byte {
	return p[20:p.DataOffset()]
}

func (p Packet) Payload() []byte {
	return p[p.DataOffset():]
}
