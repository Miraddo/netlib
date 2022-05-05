package tcp

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
