// Package tcp
package tcp

import "encoding/binary"

// resources:
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
// https://www.ibm.com/docs/en/aix/7.2?topic=protocols-tcp-header-field-definitions

// SourcePort Identifies the port number of a source application program.
func (p Packet) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p[0:])
}

// DestinationPort Identifies the port number of a destination application program.
func (p Packet) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

// SequenceNumber Specifies the sequence number of the first byte of data in this segment.
func (p Packet) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(p[4:])
}

// AckNumber Identifies the position of the highest byte received.
func (p Packet) AckNumber() uint32 {
	return binary.BigEndian.Uint32(p[8:])
}

// DataOffset Specifies the offset of data portion of the segment.
func (p Packet) DataOffset() uint8 {
	return (p[12] >> 4) * 4
}

// Window Specifies the amount of data the destination is willing to accept.
func (p Packet) Window() uint16 {
	return binary.BigEndian.Uint16(p[14:])
}

// GetChecksum Verifies the integrity of the segment header and data.
func (p Packet) GetChecksum() uint16 {
	return binary.BigEndian.Uint16(p[16:])
}

// UrgentPointer Indicates data that is to be delivered as quickly as possible.
//This pointer specifies the position where urgent data ends.
func (p Packet) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(p[18:])
}

// Options
// - End of Option List
// 	Indicates the end of the option list. It is used at the final option,
// 	not at the end of each option individually.
//	This option needs to be used only if the end of the options would not
// 	otherwise coincide with the end of the TCP header.
// - No Operation
//	Indicates boundaries between options.
//	Can be used between other options; for example,
//	to align the beginning of a subsequent option on a word boundary.
//	There is no guarantee that senders will use this option,
//	so receivers must be prepared to process options even if they do not begin
// 	on a word boundary.
// - Maximum Segment Size
//	Indicates the maximum segment size TCP can receive.
//	This is only sent in the initial connection request.
func (p Packet) Options() []byte {
	return p[20:p.DataOffset()]
}

// Payload The TCP header padding is used to ensure that the TCP header ends,
//	and data begins, on a 32-bit boundary. The padding is composed of zeros.
func (p Packet) Payload() []byte {
	return p[p.DataOffset():]
}
