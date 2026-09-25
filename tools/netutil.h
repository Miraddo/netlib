/*
 * netutil.h - small helpers shared by the netlib command line tools.
 *
 * The helpers deliberately stay free of any protocol state so every tool can
 * use them without pulling in the rest of the library.
 */
#ifndef NETLIB_NETUTIL_H
#define NETLIB_NETUTIL_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Largest frame the tools accept, big enough for a 9000 byte jumbo frame. */
#define NU_MAX_FRAME 65536

/*
 * Internet checksum, RFC 1071.
 *
 * nu_sum() returns a folded partial sum so several buffers can be chained,
 * for example a pseudo header followed by a segment. Only the last buffer of
 * a chain may have an odd length, an odd length in the middle would shift the
 * alignment of every following byte.
 *
 * nu_fold() turns a partial sum into the value that belongs on the wire, read
 * as a big endian 16 bit field. Running it over data that already carries a
 * correct checksum yields 0.
 */
uint32_t nu_sum(const void *data, size_t len, uint32_t seed);
uint16_t nu_fold(uint32_t sum);
uint16_t nu_checksum(const void *data, size_t len);

/*
 * Parses hex bytes out of text. Whitespace and the ':' '-' ',' '.' separators
 * are ignored, as is a '0x' prefix. A '#' or ';' starts a comment, and so
 * does a '|' so that annotated dumps stay readable. A run of four or more hex
 * digits followed by ':' at the start of a line is treated as an offset
 * label, which is what "tcpdump -x" prints.
 *
 * Every run of hex digits must hold an even number of digits. Returns the
 * number of bytes written, or -1 with errno set to EINVAL on malformed input
 * and ENOSPC when out is too small.
 */
ssize_t nu_parse_hex(const char *text, size_t text_len, uint8_t *out, size_t out_len);

/*
 * Reads a whole buffer from path, or from standard input when path is NULL or
 * "-". With binary set the bytes are taken as they are, otherwise they are
 * parsed as hex text. Returns the byte count, or -1 with errno set the way
 * the two readers below set it.
 */
ssize_t nu_load(const char *path, int binary, uint8_t *out, size_t out_len);

/* Reads a whole stream. Returns the byte count, or -1 with errno set. */
ssize_t nu_read_binary(FILE *fp, uint8_t *out, size_t out_len);

/* Reads a whole stream as hex text and parses it with nu_parse_hex(). */
ssize_t nu_read_hex(FILE *fp, uint8_t *out, size_t out_len);

/* Classic 16 bytes per line dump with an ascii column. */
void nu_hexdump(FILE *out, const uint8_t *data, size_t len, unsigned indent);

/* Formatting helpers. Each returns a pointer into a small ring of static
 * buffers, so a handful of calls may be mixed in one printf(), but the result
 * must not be stored for later. */
const char *nu_mac(const uint8_t mac[6]);
const char *nu_ipv4(const uint8_t addr[4]);
const char *nu_ipv6(const uint8_t addr[16]);

/* Names for well known numbers, never NULL. */
const char *nu_ether_type_name(uint16_t ether_type);
const char *nu_ip_proto_name(uint8_t proto);

/* Report layout used by the tools: a section title and its "name : value"
 * fields, both indented by indent levels of two spaces. */
void nu_section(unsigned indent, const char *fmt, ...);
void nu_field(unsigned indent, const char *name, const char *fmt, ...);

#endif /* NETLIB_NETUTIL_H */
