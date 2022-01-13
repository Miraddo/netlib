package main

import (
	"fmt"

	"github.com/miraddo/TCPHeader/header"
)

func main() {

	p := header.Packet{

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

	p.New()
	fmt.Println("Source Port: ", p.SourcePort())
	fmt.Println("Destination Port: ", p.DestinationPort())
	fmt.Println("Sequence Number: ", p.SequenceNumber())
	fmt.Println("Ack Number: ", p.AckNumber())
	fmt.Printf("data offset: %b \n", p.DO())
	fmt.Printf("Reserved data: %.3b \n", p.RSV())
	fmt.Printf("Flags Control flags: %.9b \n", p.Flags())
	fmt.Println("Window size: ", p.Window())
	fmt.Printf("Checksum %x %d\n", p.Checksum(), p.Checksum())
	fmt.Println("Urgent Pointer: ", p.UrgentPointer())

}
