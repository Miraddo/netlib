# Network Libraries

Some libraries that help us to have better life in our codes. :)

## Under implementation

## Layout

| path       | what it holds                                                      |
| ---------- | ------------------------------------------------------------------ |
| `detector` | an XDP program that reports the packets it sees, and its loader    |
| `tools`    | user space command line tools for inspecting packets and the host  |
| `docs/rfc` | the specifications the code follows                                |

## Tools

Three small tools, each one file plus the shared helpers in
`tools/netutil.c`. They only need a C compiler, libbpf is not involved.

```sh
make          # builds build/netchecksum, build/netdump, build/netifinfo
make test     # runs tools/tests.sh against frames with known fields
make clean
```

Packets are read as hex text by default, so the output of `tcpdump -x` and a
frame typed by hand both work. Offset labels at the start of a line are
skipped, `#`, `;` and `|` start a comment, and `-b` reads raw bytes instead.

### netdump

Decodes one frame and prints its headers. It knows ethernet with any number of
802.1Q tags, ARP, IPv4 with its options and fragments, IPv6 with the extension
headers that carry a length, TCP with the option kinds of `docs/rfc`, UDP, ICMP
and ICMPv6. Every checksum is verified when the buffer holds the whole packet
the length fields announce, and only then: a first fragment, for one, carries a
readable header but not the bytes the transport checksum covers. Bytes past the
announced length, ethernet padding or a second packet, are counted rather than
decoded as payload.

```sh
$ tcpdump -c1 -x -i eth0 tcp | build/netdump -q
frame length     : 74 bytes
Ethernet II
  destination      : 00:11:22:33:44:55
  source           : aa:bb:cc:dd:ee:ff
  ethertype        : 0x0800 (IPv4)
  IPv4
    version          : 4
    header length    : 20 bytes
    dscp             : 0x00
    ecn              : 0
    total length     : 60
    identification   : 0x1c46 (7238)
    flags            : DF
    fragment offset  : 0
    time to live     : 64
    protocol         : 6 (TCP)
    checksum         : 0x9c5d (valid)
    source           : 192.168.0.1
    destination      : 192.168.0.199
    TCP
      source port      : 43210
      destination port : 80
      sequence         : 3735928559
      acknowledgment   : 0
      data offset      : 40 bytes
      flags            : 0x002 (SYN)
      window           : 64240
      checksum         : 0x3fd8 (valid)
      options          : 20 bytes
        max segment size : 1460
        sack permitted   : kind 4
        timestamps       : value 287454020, echo reply 0
        no operation     : kind 1
        window scale     : 7 (multiply by 128)
```

`-l` starts at another layer for a buffer that is not a full frame, `ip`,
`tcp`, `udp` or `icmp`, and `-q` leaves the payload bytes out.

### netchecksum

Computes or verifies the internet checksum of RFC 1071, the one IPv4, ICMP,
TCP and UDP all share.

```sh
$ echo '4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7' | build/netchecksum
length           : 20 bytes
checksum         : 0xb861 (47201)
```

`-c` verifies instead, exiting non zero when the checksum is wrong, and `-s`
seeds the sum with a partial one such as a pseudo header.

### netifinfo

Lists the interfaces of the host with the index, flags, mtu and addresses, and
says which ones an XDP program can attach to.

```sh
$ build/netifinfo eth0
eth0
  index            : 4
  flags            : 0x11043 (UP BROADCAST RUNNING MULTICAST)
  mtu              : 1400
  xdp target       : yes
  hardware         : 02:fc:00:00:00:01
  inet             : 192.0.2.2/24
```

`-x` prints only the attachable names, one per line, which is the list that
belongs in the hard coded array of `detector/loader.c`.

## Detector

An XDP program that logs whether a frame carries IPv4. Building it needs
clang, libbpf and its headers, and attaching it needs root.

```sh
make detector   # builds detector.bpf.o and loader
make run        # builds both, then attaches with sudo ./loader
```

The program writes to the kernel trace pipe:

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
