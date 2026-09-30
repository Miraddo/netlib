#!/bin/sh
#
# Checks the netlib tools against frames whose every field is known, so a
# change in the decoders or in the checksum helpers shows up as a failure
# instead of as a wrong field in a report. Run it with "make test", or point
# it at a build directory: tools/tests.sh build
#
set -u

build=${1:-build}
checksum=$build/netchecksum
dump=$build/netdump
ifinfo=$build/netifinfo

failures=0
checks=0

# A tcp syn to port 80 with mss, sack permitted, timestamps and window scale.
syn='00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00 00 3c 1c 46 40 00 40 06
     9c 5d c0 a8 00 01 c0 a8 00 c7 a8 ca 00 50 de ad be ef 00 00 00 00 a0 02
     fa f0 3f d8 00 00 02 04 05 b4 04 02 08 0a 11 22 33 44 00 00 00 00 01 03
     03 07'

# An arp request for 192.168.0.199, rfc0826.
arp='ff ff ff ff ff ff aa bb cc dd ee ff 08 06 00 01 08 00 06 04 00 01 aa bb
     cc dd ee ff c0 a8 00 01 00 00 00 00 00 00 c0 a8 00 c7'

# A vlan tagged icmpv6 echo request, so the vlan, ipv6 and pseudo header
# paths are all covered by one frame.
echo6='00 11 22 33 44 55 aa bb cc dd ee ff 81 00 20 64 86 dd 60 00 00 00 00 14
       3a 40 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 20 01 0d b8 00 00
       00 00 00 00 00 00 00 00 00 02 80 00 e3 78 12 34 00 01 70 69 6e 67 20 70
       61 79 6c 6f 61 64'

# A tcp syn whose sack permitted option carries a value it must not have.
badsack='00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00 00 2c 1c 46 40 00 40 06 9c
         6d c0 a8 00 01 c0 a8 00 c7 04 d2 00 50 00 00 00 01 00 00 00 00 60 02 04 00
         10 a0 00 00 04 03 00 00'

# Udp over ipv6 with a zero checksum, which rfc2460 section 8.1 forbids.
v6nocsum='00 11 22 33 44 55 aa bb cc dd ee ff 86 dd 60 00 00 00 00 0c 11 40 20 01 0d
         b8 00 00 00 00 00 00 00 00 00 00 00 01 20 01 0d b8 00 00 00 00 00 00 00 00
         00 00 00 02 13 88 00 35 00 0c 00 00 7a 65 72 6f'

# The first fragment of a tcp datagram, MF set and the offset still zero.
frag1='00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00 00 40 1c 46 20 00 40 06 bc
         59 c0 a8 00 01 c0 a8 00 c7 04 d2 00 50 00 00 00 01 00 00 00 00 50 10 04 00
         00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14
         15 16 17'

# A short udp packet in an ethernet frame padded to the 60 byte minimum.
padded4='00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00 00 20 1c 46 40 00 40 11 9c
         6e c0 a8 00 01 c0 a8 00 c7 13 88 00 35 00 0c a5 39 61 62 63 64 00 00 00 00
         00 00 00 00 00 00 00 00 00 00'

# The same trailing bytes after an ipv6 packet.
padded6='00 11 22 33 44 55 aa bb cc dd ee ff 86 dd 60 00 00 00 00 0c 11 40 20 01 0d
         b8 00 00 00 00 00 00 00 00 00 00 00 01 20 01 0d b8 00 00 00 00 00 00 00 00
         00 00 00 02 13 88 00 35 00 0c cb dd 61 62 63 64 00 00 00 00 00 00'

# The ipv4 header of rfc1071 section 3, with and without its checksum.
rfc1071_zeroed='4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7'
rfc1071_full='4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7'

# has <name> <input> <expected text> <command...>
has() {
  name=$1
  input=$2
  expected=$3
  shift 3

  checks=$((checks + 1))
  output=$(printf '%s\n' "$input" | "$@" 2>&1)
  case $output in
  *"$expected"*)
    printf 'ok    %s\n' "$name"
    ;;
  *)
    printf 'FAIL  %s\n      wanted: %s\n' "$name" "$expected"
    printf '%s\n' "$output" | sed 's/^/      /'
    failures=$((failures + 1))
    ;;
  esac
}

# exits <name> <expected status> <input> <command...>
exits() {
  name=$1
  expected=$2
  input=$3
  shift 3

  checks=$((checks + 1))
  printf '%s\n' "$input" | "$@" >/dev/null 2>&1
  status=$?
  if [ "$status" -eq "$expected" ]; then
    printf 'ok    %s\n' "$name"
  else
    printf 'FAIL  %s\n      wanted exit %s, got %s\n' "$name" "$expected" "$status"
    failures=$((failures + 1))
  fi
}

for tool in "$checksum" "$dump" "$ifinfo"; do
  if [ ! -x "$tool" ]; then
    printf 'missing %s, build the tools first\n' "$tool" >&2
    exit 2
  fi
done

printf 'checksum\n'
has 'rfc1071 example'        "$rfc1071_zeroed" 'checksum         : 0xb861' "$checksum"
has 'rfc1071 verify'         "$rfc1071_full"   'verify           : valid'  "$checksum" -c
has 'corrupt header'         "$rfc1071_zeroed" 'verify           : invalid' "$checksum" -c
exits 'verify exit status'  1 "$rfc1071_zeroed" "$checksum" -c
exits 'valid exit status'   0 "$rfc1071_full"   "$checksum" -c
has 'seeded sum'             '01 02 03'        'seed             : 0x00000001' "$checksum" -s 1
has 'offset labels ignored'  '0x0000:  4500 0073 0000 4000
0x0010:  4011 0000 c0a8 0001
0x0020:  c0a8 00c7'                            'checksum         : 0xb861' "$checksum"
has 'comments ignored'       '4500 0073 # total length 115
0000 4000 4011 0000 ; identification and flags
c0a8 0001 c0a8 00c7'                           'checksum         : 0xb861' "$checksum"
has 'odd digit run refused'  'abc'             'not valid hex'    "$checksum"
# 65520 bytes in "tcpdump -x" shape is over 200 thousand characters, more than
# the three characters a byte the reader used to allow for.
checks=$((checks + 1))
big=$(awk 'BEGIN {
  for (i = 0; i < 65520; i += 16) {
    printf "0x%04x: ", i
    for (j = 0; j < 8; j++) printf " 4500"
    printf "\n"
  }
}')
if printf '%s\n' "$big" | "$checksum" 2>&1 | grep -q 'length           : 65520 bytes'; then
  printf 'ok    large hex input\n'
else
  printf 'FAIL  large hex input was not read whole\n'
  failures=$((failures + 1))
fi
exits 'bad input exit status' 2 'zz'            "$checksum"

printf 'ethernet and ipv4\n'
has 'ethernet source'        "$syn" 'source           : aa:bb:cc:dd:ee:ff' "$dump" -q
has 'ethertype'              "$syn" 'ethertype        : 0x0800 (IPv4)'     "$dump" -q
has 'ipv4 header checksum'   "$syn" 'checksum         : 0x9c5d (valid)'    "$dump" -q
has 'ipv4 flags'             "$syn" 'flags            : DF'                "$dump" -q
has 'ipv4 addresses'         "$syn" 'destination      : 192.168.0.199'     "$dump" -q
has 'padding is not payload' "$padded4" 'trailing bytes   : 14'              "$dump" -q
has 'payload stops at length' "$padded4" 'payload          : 4 bytes'        "$dump" -q
has 'first fragment noted'   "$frag1" 'first of several'                     "$dump" -q
has 'fragment not verified'  "$frag1" 'checksum         : 0x0000 (not verified)' "$dump" -q

printf 'tcp\n'
has 'tcp ports'              "$syn" 'destination port : 80'                "$dump" -q
has 'tcp flag names'         "$syn" 'flags            : 0x002 (SYN)'       "$dump" -q
has 'tcp checksum'           "$syn" 'checksum         : 0x3fd8 (valid)'    "$dump" -q
has 'option mss'             "$syn" 'max segment size : 1460'              "$dump" -q
has 'option sack permitted'  "$syn" 'sack permitted   : kind 4'            "$dump" -q
has 'option timestamps'      "$syn" 'timestamps       : value 287454020'   "$dump" -q
has 'option window scale'    "$syn" 'window scale     : 7 (multiply by 128)' "$dump" -q
has 'tcp without a carrier'  "$syn" 'not verified' "$dump" -q -l tcp
has 'fixed option length'    "$badsack" 'sack permitted   : malformed' "$dump" -q

printf 'arp\n'
has 'arp operation'          "$arp" 'operation        : 1 (request)'       "$dump" -q
has 'arp sender'             "$arp" 'sender           : aa:bb:cc:dd:ee:ff, 192.168.0.1' "$dump" -q
has 'broadcast destination'  "$arp" '(broadcast)'                         "$dump" -q

printf 'vlan, ipv6 and icmpv6\n'
has 'vlan tag'               "$echo6" 'vlan tag         : id 100, priority 1' "$dump" -q
has 'ipv6 source'            "$echo6" 'source           : 2001:db8::1'     "$dump" -q
has 'icmpv6 type'            "$echo6" 'type             : 128 (echo request)' "$dump" -q
has 'icmpv6 checksum'        "$echo6" 'checksum         : 0xe378 (valid)'  "$dump" -q
has 'ipv6 needs a checksum'  "$v6nocsum" 'invalid, IPv6 requires a checksum' "$dump" -q
has 'ipv6 trailing bytes'    "$padded6" 'trailing bytes   : 6'               "$dump" -q

printf 'malformed input\n'
has 'short ipv4 header'      '00 11 22 33 44 55 aa bb cc dd ee ff 08 00 45 00 00' \
                             'truncated' "$dump" -q
has 'short tcp options'      '50 00 00 50 00 00 00 00 00 00 00 00 a0 02 00 00 00 00 00 00 02' \
                             'truncated' "$dump" -q -l tcp
has 'bad tcp option length'  '50 00 00 50 00 00 00 00 00 00 00 00 60 02 00 00 00 00 00 00 02 09 00 00' \
                             'malformed' "$dump" -q -l tcp
exits 'empty input'        2 ''                "$dump"
exits 'unknown layer'      2 "$syn"            "$dump" -l ppp

printf 'interfaces\n'
checks=$((checks + 1))
if "$ifinfo" >/dev/null 2>&1; then
  printf 'ok    interface report\n'
else
  printf 'FAIL  interface report exited %s\n' "$?"
  failures=$((failures + 1))
fi
exits 'unknown interface'  1 '' "$ifinfo" definitely-not-an-interface

printf '\n%s check%s, %s failure%s\n' "$checks" "$([ "$checks" -eq 1 ] || echo s)" \
  "$failures" "$([ "$failures" -eq 1 ] || echo s)"

[ "$failures" -eq 0 ]
