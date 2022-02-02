// Package tcp
package tcp

import (
	"fmt"

	"github.com/GeniusesGroup/libgo/binary"
)

// GetSourcePort Identifies the sending port.
func (p Packet) GetSourcePort() uint16 {
	return binary.BigEndian.Uint16(p[0:2])
}

// SetSourcePort Identifies the sending port.
func (p Packet) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p[0:2], port)
}

// GetDestinationPort Identifies the receiving port.
func (p Packet) GetDestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:4])
}

// SetDestinationPort Identifies the receiving port.
func (p Packet) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:4], port)
}

// SequenceNumber Message senders use sequence numbers to mark the ordering of
// a group of messages.
func (p Packet) GetSequenceNumber() uint32 {
	return binary.BigEndian.Uint32(p[4:8])
}

// SetSequenceNumber Message senders use sequence numbers to mark the ordering of
// a group of messages.
func (p Packet) SetSequenceNumber(v uint32) {
	binary.BigEndian.PutUint32(p[4:8], v)
}

// AckNumber Acknowledgment number (4 bytes or 32 bits): Both senders and receivers
// use the acknowledgment numbers field to communicate the sequence numbers of
// messages that are either recently received or expected to be sent.
func (p Packet) GetAckNumber() uint32 {
	return binary.BigEndian.Uint32(p[8:12])
}

// AckNumber Acknowledgment number (4 bytes or 32 bits): Both senders and receivers
// use the acknowledgment numbers field to communicate the sequence numbers of
// messages that are either recently received or expected to be sent.
func (p Packet) SetAckNumber(v uint32) {
	binary.BigEndian.PutUint32(p[8:12], v)
}

// DO Specifies the size of the TCP header in 32-bit **words**.
// The minimum size header is 5 words and the maximum is 15 words thus giving
// the minimum size of 20 bytes and maximum of 60 bytes,
// allowing for up to 40 bytes of options in the header.
func (p Packet) GetDataOffset() uint8 {
	return (binary.Uint8(p[12:13]) >> 4) * 4
}

func (p Packet) SetDataOffset(v uint8) {
	if v > 0 && v < 16 {
		p[12] = byte(uint8(v<<4)) | byte(uint8(p[12]>>4))
	}
}

// ReservedData Reserved data (3 bits): Reserved data in TCP headers always has a value of zero.
// This field aligns the total header size as a multiple of four bytes,
// which is important for the efficiency of computer data processing.
func (p Packet) ReservedData() uint8 {
	return uint8(p[12]<<4) >> 1
}

// getFlags Control flags (up to 9 bits): TCP uses a set of six standard and
// three extended control flags—each an individual bit representing On or Off—to manage
// data flow in specific situations.
func (p Packet) getFlags(positon int) bool {
	switch {
	case positon == 7:
		return uint8(p[12]<<7)>>1 == 1
	default:
		return uint16(uint16(uint16(p[13])|uint16(p[12])<<8)<<positon)>>15 == 1
	}
}

// setFlags ...
func (p Packet) setFlags(positon uint8, v bool) {
	// switch {
	// case positon == 7:
	// 	if v {
	// 		p[12] = byte(p[12] | 0b00000001)
	// 		return
	// 	}

	// 	p[12] = byte(p[12] | 0b00000000)

	// default:
	// 	switch v {
	// 	case positon == 8:
	// 		p[13] = byte(p[13] | 0b10000000)
	// 		return
	// 	case positon == 9:
	// 		p[13] = byte(p[13] | 0b01000000)
	// 		return

	// 	case positon == 10:
	// 		p[13] = byte(p[13] | 0b00100000)
	// 		return

	// 	case positon == 11:
	// 		p[13] = byte(p[13] | 0b00010000)
	// 		return

	// 	case positon == 12:
	// 		p[13] = byte(p[13] | 0b00001000)
	// 		return

	// 	case positon == 13:
	// 		p[13] = byte(p[13] | 0b00000100)
	// 		return

	// 	case positon == 14:
	// 		p[13] = byte(p[13] | 0b00000010)
	// 		return

	// 	case positon == 15:
	// 		p[13] = byte(p[13] | 0b00000001)
	// 		return
	// 	}
	// }
}

// NS (1 bit): ECN-nonce - concealment protection
func (p Packet) GetFlagNS() bool {
	return p.getFlags(7)
}

func (p Packet) SetFlagNS(v bool) {
	p.setFlags(7, v)
}

// CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host
// to indicate that it received a TCP segment with the ECE flag set and had
// responded in congestion control mechanism.
func (p Packet) GetFlagCWR() bool {
	return p.getFlags(8)
}

func (p Packet) SetFlagCWR(v bool) {
	p.setFlags(8, v)
}

// ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag.
// It indicates:
// - If the SYN flag is set (1), that the TCP peer is ECN capable.
// - If the SYN flag is clear (0), that a packet with Congestion Experienced flag
//   set (ECN=11) in the IP header was received during normal transmission.
//   This serves as an indication of network congestion (or impending congestion) to the TCP sender.
func (p Packet) GetFlagECE() bool {
	return p.getFlags(9)
}

func (p Packet) SetFlagECE(v bool) {
	p.setFlags(9, v)
}

// URG (1 bit): Indicates that the Urgent pointer field is significant.
func (p Packet) GetFlagURG() bool {
	return p.getFlags(10)
}

func (p Packet) SetFlagURG(v bool) {
	p.setFlags(10, v)
}

// ACK (1 bit): Indicates that the Acknowledgment field is significant.
// All packets after the initial SYN packet sent by the client should have this flag set.
func (p Packet) GetFlagACK() bool {
	return p.getFlags(11)
}

func (p Packet) SetFlagACK(v bool) {
	p.setFlags(11, v)
}

// PSH (1 bit): Push function. Asks to push the buffered data to the receiving application.
func (p Packet) GetFlagPSH() bool {
	return p.getFlags(12)
}

func (p Packet) SetFlagPSH(v bool) {
	p.setFlags(12, v)
}

// RST (1 bit): Reset the connection.
func (p Packet) GetFlagRST() bool {
	return p.getFlags(13)
}

func (p Packet) SetFlagRST(v bool) {
	p.setFlags(13, v)
}

// SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from
// each end should have this flag set. Some other flags and fields change meaning
// based on this flag, and some are only valid when it is set, and others when it is clear.
func (p Packet) GetFlagSYN() bool {
	return p.getFlags(14)
}

func (p Packet) SetFlagSYN(v bool) {
	p.setFlags(14, v)
}

// FIN (1 bit): Last packet from sender.
func (p Packet) GetFlagFIN() bool {
	return p.getFlags(15)
}

func (p Packet) SetFlagFIN(v bool) {
	p.setFlags(15, v)
}

// Window specifies the number of window size units[c] that the sender of this
// segment is currently willing to receive.
func (p Packet) GetWindow() uint16 {
	return uint16(uint16(p[15]) | uint16(p[14])<<8)
}

func (p Packet) SetWindow(v uint16) {
	binary.BigEndian.PutUint16(p[14:16], v)
}

// Checksum TCP checksum (2 bytes or 16 bits): The checksum value inside
// a TCP header is generated by the protocol sender as a mathematical technique
// to help the receiver detect messages that are corrupted or tampered with.
func (p Packet) GetChecksum() uint16 {
	return binary.BigEndian.Uint16(p[16:18])
}

func (p Packet) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(p[16:18], v)
}

// UrgentPointer Urgent pointer (2 bytes or 16 bits): The urgent pointer field
// is often set to zero and ignored, but in conjunction with one of the control
// flags, it can be used as a data offset to mark a subset of a message as
// requiring priority processing.
func (p Packet) GetUrgentPointer() uint16 {
	return binary.BigEndian.Uint16(p[18:20])
}

func (p Packet) SetUrgentPointer(v uint16) {
	binary.BigEndian.PutUint16(p[18:20], v)
}

// Options TCP optional data (0 to 40 bytes): Usages of optional TCP data
// include support for special acknowledgment and window scaling algorithms.
func (p *Packet) Options() {
	fmt.Println("Options")
}
