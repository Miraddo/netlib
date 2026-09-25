#include "netutil.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t nu_sum(const void *data, size_t len, uint32_t seed) {
  const uint8_t *bytes = data;
  uint32_t sum = seed;
  size_t i;

  for (i = 0; i + 1 < len; i += 2)
    sum += (uint32_t)bytes[i] << 8 | bytes[i + 1];

  /* A trailing odd byte is padded on the right with a zero byte. */
  if (i < len)
    sum += (uint32_t)bytes[i] << 8;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return sum;
}

uint16_t nu_fold(uint32_t sum) {
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return (uint16_t)~sum;
}

uint16_t nu_checksum(const void *data, size_t len) {
  return nu_fold(nu_sum(data, len, 0));
}

static int hex_value(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  return -1;
}

ssize_t nu_parse_hex(const char *text, size_t text_len, uint8_t *out, size_t out_len) {
  size_t i = 0, written = 0;
  int line_start = 1;

  while (i < text_len) {
    unsigned char c = (unsigned char)text[i];

    if (c == '\n') {
      line_start = 1;
      i++;
      continue;
    }

    /* Comments make annotated dumps usable as input. */
    if (c == '#' || c == ';' || c == '|') {
      while (i < text_len && text[i] != '\n')
        i++;
      continue;
    }

    if (isspace(c)) {
      i++;
      continue;
    }

    if (c == ':' || c == '-' || c == ',' || c == '.') {
      i++;
      line_start = 0;
      continue;
    }

    if (c == '0' && i + 1 < text_len && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
      i += 2;
      continue;
    }

    if (hex_value(c) < 0) {
      errno = EINVAL;
      return -1;
    }

    size_t start = i;
    while (i < text_len && hex_value((unsigned char)text[i]) >= 0)
      i++;
    size_t run = i - start;

    /* "0000:" or "0x0000:" at the start of a line is an offset label, the
     * shape "tcpdump -x" prints. Short runs are left alone so that a mac
     * address written with ':' separators still parses. */
    if (line_start && run >= 4 && i < text_len && text[i] == ':') {
      i++;
      line_start = 0;
      continue;
    }
    line_start = 0;

    if (run % 2 != 0) {
      errno = EINVAL;
      return -1;
    }

    for (size_t j = 0; j < run; j += 2) {
      if (written >= out_len) {
        errno = ENOSPC;
        return -1;
      }
      out[written++] = (uint8_t)(hex_value((unsigned char)text[start + j]) << 4 |
                                 hex_value((unsigned char)text[start + j + 1]));
    }
  }

  return (ssize_t)written;
}

ssize_t nu_load(const char *path, int binary, uint8_t *out, size_t out_len) {
  FILE *fp = stdin;

  if (path && strcmp(path, "-") != 0) {
    fp = fopen(path, binary ? "rb" : "r");
    if (!fp)
      return -1;
  }

  ssize_t len = binary ? nu_read_binary(fp, out, out_len) : nu_read_hex(fp, out, out_len);
  int saved = errno;

  if (fp != stdin)
    fclose(fp);
  errno = saved;

  return len;
}

ssize_t nu_read_binary(FILE *fp, uint8_t *out, size_t out_len) {
  size_t total = 0;

  while (total < out_len) {
    size_t n = fread(out + total, 1, out_len - total, fp);
    total += n;
    if (n == 0)
      break;
  }

  if (ferror(fp))
    return -1;

  /* Anything left in the stream would be silently dropped. */
  if (total == out_len && getc(fp) != EOF) {
    errno = ENOSPC;
    return -1;
  }

  return (ssize_t)total;
}

ssize_t nu_read_hex(FILE *fp, uint8_t *out, size_t out_len) {
  /* Two hex digits plus a separator per byte is a safe upper bound. */
  size_t text_len = out_len * 3 + 1;
  char *text = malloc(text_len);
  if (!text)
    return -1;

  size_t total = 0;
  while (total < text_len) {
    size_t n = fread(text + total, 1, text_len - total, fp);
    total += n;
    if (n == 0)
      break;
  }

  ssize_t parsed;
  if (ferror(fp)) {
    parsed = -1;
  } else if (total == text_len && getc(fp) != EOF) {
    /* More text than a full buffer of bytes could ever need. */
    errno = ENOSPC;
    parsed = -1;
  } else {
    parsed = nu_parse_hex(text, total, out, out_len);
  }

  int saved = errno;
  free(text);
  errno = saved;

  return parsed;
}

void nu_hexdump(FILE *out, const uint8_t *data, size_t len, unsigned indent) {
  for (size_t offset = 0; offset < len; offset += 16) {
    size_t line = len - offset < 16 ? len - offset : 16;

    fprintf(out, "%*s%04zx  ", (int)(indent * 2), "", offset);
    for (size_t i = 0; i < 16; i++) {
      if (i < line)
        fprintf(out, "%02x ", data[offset + i]);
      else
        fputs("   ", out);
      if (i == 7)
        fputc(' ', out);
    }

    fputs(" |", out);
    for (size_t i = 0; i < line; i++) {
      unsigned char c = data[offset + i];
      fputc(isprint(c) ? c : '.', out);
    }
    fputs("|\n", out);
  }
}

/* Small rings of buffers so that a source and a destination address can be
 * formatted in the same printf() call. */
#define NU_RING 4

const char *nu_mac(const uint8_t mac[6]) {
  static char buf[NU_RING][18];
  static unsigned next;
  char *slot = buf[next++ % NU_RING];

  snprintf(slot, sizeof(buf[0]), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);

  return slot;
}

const char *nu_ipv4(const uint8_t addr[4]) {
  static char buf[NU_RING][16];
  static unsigned next;
  char *slot = buf[next++ % NU_RING];

  snprintf(slot, sizeof(buf[0]), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);

  return slot;
}

const char *nu_ipv6(const uint8_t addr[16]) {
  static char buf[NU_RING][40];
  static unsigned next;
  char *slot = buf[next++ % NU_RING];

  /* RFC 5952 shortens the longest run of zero groups to "::". */
  uint16_t group[8];
  for (int i = 0; i < 8; i++)
    group[i] = (uint16_t)(addr[i * 2] << 8 | addr[i * 2 + 1]);

  int best = -1, best_len = 0;
  for (int i = 0; i < 8; i++) {
    if (group[i] != 0)
      continue;
    int run = 0;
    while (i + run < 8 && group[i + run] == 0)
      run++;
    if (run > best_len) {
      best = i;
      best_len = run;
    }
    i += run - 1;
  }
  if (best_len < 2)
    best = -1;

  size_t used = 0;
  int i = 0;
  while (i < 8) {
    if (i == best) {
      /* The "::" carries the separator on both of its sides. */
      used += (size_t)snprintf(slot + used, sizeof(buf[0]) - used, "::");
      i += best_len;
      continue;
    }
    used += (size_t)snprintf(slot + used, sizeof(buf[0]) - used, "%x", group[i]);
    i++;
    if (i < 8 && i != best)
      used += (size_t)snprintf(slot + used, sizeof(buf[0]) - used, ":");
  }

  return slot;
}

const char *nu_ether_type_name(uint16_t ether_type) {
  switch (ether_type) {
  case 0x0800: return "IPv4";
  case 0x0806: return "ARP";
  case 0x8035: return "RARP";
  case 0x8100: return "802.1Q VLAN";
  case 0x86dd: return "IPv6";
  case 0x8808: return "Ethernet flow control";
  case 0x8847: return "MPLS unicast";
  case 0x8863: return "PPPoE discovery";
  case 0x8864: return "PPPoE session";
  case 0x88a8: return "802.1ad QinQ";
  case 0x88cc: return "LLDP";
  case 0x88f7: return "PTP";
  default: return "unknown";
  }
}

const char *nu_ip_proto_name(uint8_t proto) {
  switch (proto) {
  case 0: return "HOPOPT";
  case 1: return "ICMP";
  case 2: return "IGMP";
  case 4: return "IPv4";
  case 6: return "TCP";
  case 17: return "UDP";
  case 41: return "IPv6";
  case 43: return "IPv6 route";
  case 44: return "IPv6 fragment";
  case 47: return "GRE";
  case 50: return "ESP";
  case 51: return "AH";
  case 58: return "ICMPv6";
  case 59: return "IPv6 no next header";
  case 60: return "IPv6 destination options";
  case 89: return "OSPF";
  case 103: return "PIM";
  case 112: return "VRRP";
  case 132: return "SCTP";
  case 136: return "UDPLite";
  default: return "unknown";
  }
}

void nu_section(unsigned indent, const char *fmt, ...) {
  va_list args;

  printf("%*s", (int)(indent * 2), "");
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  putchar('\n');
}

void nu_field(unsigned indent, const char *name, const char *fmt, ...) {
  va_list args;

  printf("%*s%-16s : ", (int)(indent * 2), "", name);
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  putchar('\n');
}
