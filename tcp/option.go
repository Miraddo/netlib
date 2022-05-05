package tcp

type Options []byte

func (o Options) HasNext() bool {
	return len(o) > 0
}

//func (o Options) Next() (opt Option, remain Options) {
//
//}

type Option struct {
	Kind   OptionKind
	Length uint8
	Data   []byte
}

// OptionKind represents a TCP option kind code.
type OptionKind uint8

// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
const (
	OptionKindEndList OptionKind = iota
	OptionKindNop
	OptionKindMSS                             // len = 4, Maximum Segment Size
	OptionKindWindowScale                     // len = 3
	OptionKindSACKPermitted                   // len = 2
	OptionKindSACK                            // len = n
	OptionKindEcho                            // len = 6, obsolete
	OptionKindEchoReply                       // len = 6, obsolete
	OptionKindTimestamps                      // len = 10
	OptionKindPartialOrderConnectionPermitted // len = 2, obsolete
	OptionKindPartialOrderServiceProfile      // len = 3, obsolete
	OptionKindCC                              // obsolete
	OptionKindCCNew                           // obsolete
	OptionKindCCEcho                          // obsolete
	OptionKindAltChecksum                     // len = 3, obsolete
	OptionKindAltChecksumData                 // len = n, obsolete
)
