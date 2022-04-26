package tcp

func (p Packet) FlagReserved1() bool {
	return p[12]&FlagReserved1 != 0
}

func (p Packet) FlagReserved2() bool {
	return p[12]&FlagReserved2 != 0
}

func (p Packet) FlagReserved3() bool {
	return p[12]&FlagReserved3 != 0
}

func (p Packet) FlagNS() bool {
	return p[12]&FlagNS != 0
}

func (p Packet) FlagCWR() bool {
	return p[13]&FlagCWR != 0
}

func (p Packet) FlagECE() bool {
	return p[13]&FlagECE != 0
}

func (p Packet) FlagURG() bool {
	return p[13]&FlagURG != 0
}

func (p Packet) FlagACK() bool {
	return p[13]&FlagACK != 0
}

func (p Packet) FlagPSH() bool {
	return p[13]&FlagPSH != 0
}

func (p Packet) FlagRST() bool {
	return p[13]&FlagRST != 0
}

func (p Packet) FlagSYN() bool {
	return p[13]&FlagSYN != 0
}

func (p Packet) FlagFIN() bool {
	return p[13]&FlagFIN != 0
}
