package main

import (
	"fmt"

	"github.com/miraddo/TCPHeader/header"
)

func main() {

	p := header.Packet{
		0xb7, 0x4e, 0x01, 0xbb, 0xb1, 0x46, 0xa4, 0x61, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfa, 0xf0,
		0x9b, 0xba, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xaa, 0xd5, 0x92, 0xe4,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
	}

	fmt.Println("Source Port: ", p.SourcePort())
	fmt.Println("Destination Port: ", p.DestinationPort())
	fmt.Println("Sequence Number: ", p.SequenceNumber())
	fmt.Println("Ack Number: ", p.AckNumber())
	fmt.Printf("data offset: %b \n", p.DO())
	fmt.Printf("Reserved data: %.3b \n", p.RSV())
	fmt.Printf("Flags Control flags: %v \n", p.Flags())
	fmt.Println("Window size: ", p.Window())
	fmt.Printf("Checksum %x %d\n", p.Checksum(), p.Checksum())
	fmt.Println("Urgent Pointer: ", p.UrgentPointer())

}
