package tcp

import (
	"fmt"
	"log"
	"strconv"
)

func (w *Writer) Build() []byte {
	var result []byte

	sp, err := strconv.Atoi(fmt.Sprintf("%x", w.SourcePort))

	result = append(result, byte(sp))
	result = append(result, []byte(strconv.FormatInt(int64(w.DestinationPort), 16))...)
	result = append(result, []byte(strconv.FormatInt(int64(w.SequenceNumber), 16))...)
	result = append(result, []byte(strconv.FormatInt(int64(w.AckNumber), 16))...)
	bits := fmt.Sprintf("%b", w.DataOffset)
	bits = bits + fmt.Sprintf("%b", w.ReservedData)

	switch {
	case !w.Flags.SYN:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}

	switch {
	case !w.Flags.ACK:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}

	switch {
	case !w.Flags.RST:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}

	switch {
	case !w.Flags.FIN:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}

	switch {
	case !w.Flags.PSH:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}

	switch {
	case !w.Flags.URG:
		bits = bits + "0"

	default:
		bits = bits + "1"
	}
	fg, err := strconv.Atoi(bits)
	if err != nil {
		log.Fatalf("got an error %v", err)
	}
	result = append(result, []byte(strconv.FormatInt(int64(fg), 16))...)
	result = append(result, []byte(strconv.FormatInt(int64(w.Window), 16))...)
	result = append(result, []byte(strconv.FormatInt(int64(w.Checksum), 16))...)
	result = append(result, []byte(strconv.FormatInt(int64(w.UrgentPointer), 16))...)

	return result
}
