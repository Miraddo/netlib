package tcp

import "encoding/binary"

func (p Packet) SetSourcePort(port uint16)      { binary.BigEndian.PutUint16(p[0:], port) }
func (p Packet) SetDestinationPort(port uint16) { binary.BigEndian.PutUint16(p[2:], port) }
func (p Packet) SetSequenceNumber(v uint32)     { binary.BigEndian.PutUint32(p[4:], v) }
func (p Packet) SetAckNumber(v uint32)          { binary.BigEndian.PutUint32(p[8:], v) }
func (p Packet) SetDataOffset(v uint8)          { p[12] = byte((v/4)<<4) | p[12] }
func (p Packet) SetFlagPartOne(flags byte)      { p[12] = p[12] | flags }
func (p Packet) SetFlagPartTwo(flags byte)      { p[13] = flags }
func (p Packet) SetWindow(v uint16)             { binary.BigEndian.PutUint16(p[14:], v) }
func (p Packet) SetChecksum(v uint16)           { binary.BigEndian.PutUint16(p[16:], v) }
func (p Packet) SetUrgentPointer(v uint16)      { binary.BigEndian.PutUint16(p[18:], v) }
func (p Packet) SetOptions(o []byte)            { copy(p[20:], o) }
func (p Packet) SetPayload(payload []byte)      { copy(p[p.DataOffset():], payload) }
