package tcp

type Packet []byte

type Writer struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffset      uint8
	ReservedData    uint8
	Flags           struct {
		SYN bool
		ACK bool
		RST bool
		FIN bool
		PSH bool
		URG bool
	}
	Window        uint16
	Checksum      uint16
	UrgentPointer uint16
}
