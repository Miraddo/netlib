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

// =============================================================================
// TCP Header Flags Reader

func (p Packet) FlagReserved1() bool { return p[12]&FlagReserved1 != 0 }
func (p Packet) FlagReserved2() bool { return p[12]&FlagReserved2 != 0 }
func (p Packet) FlagReserved3() bool { return p[12]&FlagReserved3 != 0 }
func (p Packet) FlagNS() bool        { return p[12]&FlagNS != 0 }
func (p Packet) FlagCWR() bool       { return p[13]&FlagCWR != 0 }
func (p Packet) FlagECE() bool       { return p[13]&FlagECE != 0 }
func (p Packet) FlagURG() bool       { return p[13]&FlagURG != 0 }
func (p Packet) FlagACK() bool       { return p[13]&FlagACK != 0 }
func (p Packet) FlagPSH() bool       { return p[13]&FlagPSH != 0 }
func (p Packet) FlagRST() bool       { return p[13]&FlagRST != 0 }
func (p Packet) FlagSYN() bool       { return p[13]&FlagSYN != 0 }
func (p Packet) FlagFIN() bool       { return p[13]&FlagFIN != 0 }

// =============================================================================
// TCP Header Flags Writer

func (p Packet) SetFlagReserved1() { p[12] |= FlagReserved1 }
func (p Packet) SetFlagReserved2() { p[12] |= FlagReserved2 }
func (p Packet) SetFlagReserved3() { p[12] |= FlagReserved3 }
func (p Packet) SetFlagNS()        { p[12] |= FlagNS }
func (p Packet) SetFlagCWR()       { p[13] |= FlagCWR }
func (p Packet) SetFlagECE()       { p[13] |= FlagECE }
func (p Packet) SetFlagURG()       { p[13] |= FlagURG }
func (p Packet) SetFlagACK()       { p[13] |= FlagACK }
func (p Packet) SetFlagPSH()       { p[13] |= FlagPSH }
func (p Packet) SetFlagRST()       { p[13] |= FlagRST }
func (p Packet) SetFlagSYN()       { p[13] |= FlagSYN }
func (p Packet) SetFlagFIN()       { p[13] |= FlagFIN }
