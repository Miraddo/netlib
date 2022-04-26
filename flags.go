package tcp

const (
	FlagReserved1 byte = 0b00001000
	FlagReserved2 byte = 0b00000100
	FlagReserved3 byte = 0b00000010
	FlagNS        byte = 0b00000001
	FlagCWR       byte = 0b10000000
	FlagECE       byte = 0b01000000
	FlagURG       byte = 0b00100000
	FlagACK       byte = 0b00010000
	FlagPSH       byte = 0b00001000
	FlagRST       byte = 0b00000100
	FlagSYN       byte = 0b00000010
	FlagFIN       byte = 0b00000001
)

type Flags struct {
	Reserved1, Reserved2, Reserved3 bool
	NS                              bool
	CWR                             bool
	ECE                             bool
	URG                             bool
	ACK                             bool
	PSH                             bool
	RST                             bool
	SYN                             bool
	FIN                             bool
}
