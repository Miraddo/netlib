package tcp

import "encoding/binary"

type Packet []byte

type Header struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffset      uint8
	Flags           Flags
	Window          uint16
	Checksum        uint16
	UrgentPointer   uint16
	Options         []Option
	Padding         []byte
	Payload         []byte
}

// =============================================================================
// TCP Header Reader

func (p Packet) SourcePort() uint16      { return binary.BigEndian.Uint16(p[0:]) }
func (p Packet) DestinationPort() uint16 { return binary.BigEndian.Uint16(p[2:]) }
func (p Packet) SequenceNumber() uint32  { return binary.BigEndian.Uint32(p[4:]) }
func (p Packet) AckNumber() uint32       { return binary.BigEndian.Uint32(p[8:]) }
func (p Packet) DataOffset() uint8       { return (p[12] >> 4) * 4 }
func (p Packet) Window() uint16          { return binary.BigEndian.Uint16(p[14:]) }
func (p Packet) GetChecksum() uint16     { return binary.BigEndian.Uint16(p[16:]) }
func (p Packet) UrgentPointer() uint16   { return binary.BigEndian.Uint16(p[18:]) }
func (p Packet) Options() []byte         { return p[20:p.DataOffset()] }
func (p Packet) Payload() []byte         { return p[p.DataOffset():] }

// =============================================================================
// TCP Header Writer

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
