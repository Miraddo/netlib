package tcp

import "encoding/binary"

// TCP Selective Acknowledgment Options
// https://datatracker.ietf.org/doc/html/rfc2018

type optionSACK []byte

func (o optionSACK) Length() byte       { return o[0] }
func (o optionSACK) SACK() uint16       { return binary.BigEndian.Uint16(o[1:]) }
func (o optionSACK) NextOption() []byte { return o[63:] } // wrong

func (o optionSACK) Process(s *Socket) error {
	return nil
}
