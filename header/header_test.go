package header_test

import (
	"reflect"
	"testing"

	header "github.com/miraddo/TCPHeader/header"
)

func TestWriter(t *testing.T) {
	var w header.Writer

	w = header.Writer{
		SourcePort:      46926,
		DestinationPort: 443,
		SequenceNumber:  2974196833,
		AckNumber:       0,
		DataOffset:      10,
		ReservedData:    000,
		Flags: struct {
			SYN bool
			ACK bool
			RST bool
			FIN bool
			PSH bool
			URG bool
		}{
			SYN: true,
			ACK: false,
			RST: false,
			FIN: false,
			PSH: false,
			URG: false,
		},
		Window:        64240,
		Checksum:      0x9bba,
		UrgentPointer: 0,
	}

	check := []byte{
		0xb7, 0x4e,
		0x01, 0xbb,
		0xb1, 0x46,
		0xa4, 0x61,
		0x00, 0x00,
		0x00, 0x00,
		0xa0, 0x02,
		0xfa, 0xf0,
		0x9b, 0xba,
		0x00, 0x00,
	}

	t.Log("TCP Header Writer")
	{
		if !reflect.DeepEqual(w.Build(), check) {
			t.Error("\n", w.Build(), "\n", check)
		}
	}
}
