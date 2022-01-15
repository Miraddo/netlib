package header

import (
	"testing"
)

const succeed = "\u2713"
const failed = "\u2717"

// TestReader
func TestReader(t *testing.T) {

	p := Packet{

		Header: []byte{
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
		},
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

	t.Log("Checking data offset value")
	{

		var expected uint8 = 10
		res := p.DO()

		if res != expected {
			t.Fatalf("\t%s\tExpected %d, but got %d", failed, expected, res)
		}
		t.Logf("\t%s\tEverything is looks fine ", succeed)

	}

	t.Log("Checking riversed offset value")
	{

		var expected uint8 = 000
		res := p.RSV()

		if res != expected {
			t.Fatalf("\t%s\tExpected %d, but got %d", failed, expected, res)
		}
		t.Logf("\t%s\tEverything is looks fine ", succeed)

	}

}

func BenchmarkReader(b *testing.B) {
	p := Packet{

		Header: []byte{
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
		},
	}

	b.Run("Source Port", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.SourcePort()

		}
	})

	b.Run("Destination Port", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.DestinationPort()

		}
	})

	b.Run("Sequence Number", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.SequenceNumber()

		}
	})

	b.Run("Acknowledge Number", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.AckNumber()

		}
	})

	b.Run("Data Offset", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.DO()

		}
	})

	b.Run("Window", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.Window()

		}
	})

	b.Run("Checksum", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.Checksum()

		}
	})

	b.Run("Urgent Pointer", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			p.UrgentPointer()

		}
	})
}
