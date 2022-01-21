package header

import (
	"testing"
)

const succeed = "\u2713"
const failed = "\u2717"

// TestReader
func TestReader(t *testing.T) {

	p := Packet{

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

	t.Log("Checking source port value")
	{

		var expected uint16 = 46926

		res := p.SourcePort()

		if res != expected {
			t.Fatalf("\t%s\tExpected %d, but got %d", failed, expected, res)
		}
		t.Logf("\t%s\tEverything is looks fine ", succeed)

	}

}

func BenchmarkReader(b *testing.B) {
	p := Packet{

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

	for n := 0; n < b.N; n++ {

		p.SourcePort()
		p.DestinationPort()
		p.SequenceNumber()
		p.AckNumber()
		p.DO()
		p.RSV()
		p.RSV()
		p.Flags()
		p.Window()
		p.Checksum()
		p.UrgentPointer()

	}

}
