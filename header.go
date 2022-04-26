package tcp

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
