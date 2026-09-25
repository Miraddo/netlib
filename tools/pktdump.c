/*
 * netdump - decodes a single frame or packet given as hex text or raw bytes.
 *
 * The decoder reads every field by offset instead of casting kernel structs
 * over the buffer, which keeps it independent of the host byte order and of
 * the headers a given system happens to ship. Header checksums are verified
 * whenever the buffer holds the whole packet the length fields announce.
 *
 * Layout and field names follow the specifications kept in docs/rfc:
 * IPv4 and TCP in rfc0793 and rfc1122, the TCP options in rfc1323 (window
 * scale, timestamps), rfc2018 (selective acknowledgment), rfc1146
 * (alternate checksum), rfc1644 (transaction extensions) and rfc2385 (md5),
 * ARP in rfc0826, IPv6 in rfc2460.
 */
#include "netutil.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int quiet; /* -q, leave the payload dump out */

static void usage(FILE *out, const char *name) {
  fprintf(out,
          "usage: %s [-b] [-q] [-l layer] [-h] [file]\n"
          "\n"
          "Decodes one frame or packet and prints its headers.\n"
          "Without a file the bytes are read from standard input as hex text,\n"
          "so \"tcpdump -x\" output and hand written frames both work.\n"
          "\n"
          "  -b         read raw binary instead of hex text\n"
          "  -l layer   first header in the buffer: eth, ip, tcp, udp, icmp\n"
          "             (default eth)\n"
          "  -q         do not dump the payload bytes\n"
          "  -h         print this help\n",
          name);
}

/* Reports a header that the buffer cannot hold. */
static int truncated(unsigned indent, const char *what, size_t have, size_t need) {
  nu_field(indent, "truncated", "%s needs %zu byte%s, only %zu left", what, need,
           need == 1 ? "" : "s", have);
  return 0;
}

static void dump_payload(const uint8_t *data, size_t len, size_t claimed, unsigned indent) {
  if (len == 0 && claimed == 0)
    return;

  if (claimed > len)
    nu_field(indent, "payload", "%zu byte%s, %zu captured", claimed,
             claimed == 1 ? "" : "s", len);
  else
    nu_field(indent, "payload", "%zu byte%s", len, len == 1 ? "" : "s");

  if (!quiet && len > 0)
    nu_hexdump(stdout, data, len, indent + 1);
}

static uint16_t be16(const uint8_t *p) {
  return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Pseudo headers of rfc0793 section 3.1 and rfc2460 section 8.1. */
static uint32_t pseudo_ipv4(const uint8_t src[4], const uint8_t dst[4], uint8_t proto,
                            uint16_t upper_len) {
  uint8_t buf[12];

  memcpy(buf, src, 4);
  memcpy(buf + 4, dst, 4);
  buf[8] = 0;
  buf[9] = proto;
  buf[10] = (uint8_t)(upper_len >> 8);
  buf[11] = (uint8_t)upper_len;

  return nu_sum(buf, sizeof(buf), 0);
}

static uint32_t pseudo_ipv6(const uint8_t src[16], const uint8_t dst[16], uint8_t proto,
                            uint32_t upper_len) {
  uint8_t buf[40];

  memcpy(buf, src, 16);
  memcpy(buf + 16, dst, 16);
  buf[32] = (uint8_t)(upper_len >> 24);
  buf[33] = (uint8_t)(upper_len >> 16);
  buf[34] = (uint8_t)(upper_len >> 8);
  buf[35] = (uint8_t)upper_len;
  buf[36] = 0;
  buf[37] = 0;
  buf[38] = 0;
  buf[39] = proto;

  return nu_sum(buf, sizeof(buf), 0);
}

/* What an upper layer decoder needs to know about the packet carrying it. */
typedef struct {
  int has_pseudo;    /* the pseudo header sum below is usable */
  uint32_t pseudo;   /* sum of the pseudo header without the length */
  int complete;      /* the buffer holds every byte the length fields claim */
  size_t claimed;    /* length the network layer announced */
} carrier;

static const carrier no_carrier = { 0, 0, 0, 0 };

static void dump_tcp_options(const uint8_t *opt, size_t len, unsigned indent);
static void dump_upper(uint8_t proto, const uint8_t *data, size_t len, const carrier *from,
                       unsigned indent);

static void dump_tcp(const uint8_t *data, size_t len, const carrier *from, unsigned indent) {
  nu_section(indent, "TCP");
  if (len < 20) {
    truncated(indent + 1, "the TCP header", len, 20);
    return;
  }

  unsigned data_offset = (data[12] >> 4) * 4u;
  uint16_t flags = (uint16_t)((data[12] & 0x01) << 8 | data[13]);
  static const struct {
    uint16_t bit;
    const char *name;
  } flag_names[] = {
    { 0x100, "NS" }, { 0x080, "CWR" }, { 0x040, "ECE" }, { 0x020, "URG" },
    { 0x010, "ACK" }, { 0x008, "PSH" }, { 0x004, "RST" }, { 0x002, "SYN" },
    { 0x001, "FIN" },
  };
  char flag_text[64];
  size_t used = 0;
  for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
    if (!(flags & flag_names[i].bit))
      continue;
    used += (size_t)snprintf(flag_text + used, sizeof(flag_text) - used, "%s%s",
                             used ? " " : "", flag_names[i].name);
  }
  if (used == 0)
    snprintf(flag_text, sizeof(flag_text), "none");

  nu_field(indent + 1, "source port", "%u", be16(data));
  nu_field(indent + 1, "destination port", "%u", be16(data + 2));
  nu_field(indent + 1, "sequence", "%u", be32(data + 4));
  nu_field(indent + 1, "acknowledgment", "%u", be32(data + 8));
  nu_field(indent + 1, "data offset", "%u byte%s", data_offset, data_offset == 1 ? "" : "s");
  nu_field(indent + 1, "flags", "0x%03x (%s)", flags, flag_text);
  nu_field(indent + 1, "window", "%u", be16(data + 14));

  uint16_t checksum = be16(data + 16);
  if (from->has_pseudo && from->complete) {
    /* The pseudo header sum still needs the segment length added to it. */
    uint16_t folded = nu_fold(nu_sum(data, from->claimed,
                                     from->pseudo + (uint32_t)from->claimed));
    nu_field(indent + 1, "checksum", "0x%04x (%s)", checksum,
             folded == 0 ? "valid" : "invalid");
  } else {
    nu_field(indent + 1, "checksum", "0x%04x (not verified)", checksum);
  }

  if (flags & 0x020)
    nu_field(indent + 1, "urgent pointer", "%u", be16(data + 18));

  if (data_offset < 20) {
    nu_field(indent + 1, "options", "invalid data offset");
    return;
  }

  if (data_offset > 20) {
    size_t option_len = data_offset - 20;
    if (option_len > len - 20) {
      truncated(indent + 1, "the TCP options", len - 20, option_len);
      return;
    }
    nu_field(indent + 1, "options", "%zu byte%s", option_len, option_len == 1 ? "" : "s");
    dump_tcp_options(data + 20, option_len, indent + 2);
  }

  if (len > data_offset) {
    size_t claimed = from->claimed > data_offset ? from->claimed - data_offset : 0;
    dump_payload(data + data_offset, len - data_offset, claimed, indent + 1);
  }
}

static void dump_tcp_options(const uint8_t *opt, size_t len, unsigned indent) {
  size_t i = 0;

  while (i < len) {
    uint8_t kind = opt[i];

    if (kind == 0) {
      nu_field(indent, "end of list", "kind 0");
      return;
    }
    if (kind == 1) {
      nu_field(indent, "no operation", "kind 1");
      i++;
      continue;
    }

    if (i + 1 >= len) {
      nu_field(indent, "malformed", "kind %u has no length byte", kind);
      return;
    }

    uint8_t option_len = opt[i + 1];
    if (option_len < 2 || i + option_len > len) {
      nu_field(indent, "malformed", "kind %u claims %u byte%s", kind, option_len,
               option_len == 1 ? "" : "s");
      return;
    }

    const uint8_t *value = opt + i + 2;
    size_t value_len = option_len - 2u;

    switch (kind) {
    case 2:
      if (value_len == 2)
        nu_field(indent, "max segment size", "%u", be16(value));
      else
        nu_field(indent, "max segment size", "malformed, %zu byte value", value_len);
      break;
    case 3:
      if (value_len == 1)
        nu_field(indent, "window scale", "%u (multiply by %u)", value[0],
                 1u << (value[0] & 0x1f));
      else
        nu_field(indent, "window scale", "malformed, %zu byte value", value_len);
      break;
    case 4:
      nu_field(indent, "sack permitted", "kind 4");
      break;
    case 5:
      if (value_len % 8 == 0 && value_len > 0) {
        for (size_t b = 0; b < value_len; b += 8)
          nu_field(indent, "sack block", "%u - %u", be32(value + b), be32(value + b + 4));
      } else {
        nu_field(indent, "sack", "malformed, %zu byte value", value_len);
      }
      break;
    case 6:
      if (value_len == 4)
        nu_field(indent, "echo", "%u", be32(value));
      else
        nu_field(indent, "echo", "malformed, %zu byte value", value_len);
      break;
    case 7:
      if (value_len == 4)
        nu_field(indent, "echo reply", "%u", be32(value));
      else
        nu_field(indent, "echo reply", "malformed, %zu byte value", value_len);
      break;
    case 8:
      if (value_len == 8)
        nu_field(indent, "timestamps", "value %u, echo reply %u", be32(value),
                 be32(value + 4));
      else
        nu_field(indent, "timestamps", "malformed, %zu byte value", value_len);
      break;
    case 9:
      nu_field(indent, "partial order permitted", "kind 9");
      break;
    case 10:
      nu_field(indent, "partial order profile", "kind 10");
      break;
    case 11:
      if (value_len == 4)
        nu_field(indent, "connection count", "%u", be32(value));
      else
        nu_field(indent, "connection count", "malformed, %zu byte value", value_len);
      break;
    case 12:
      if (value_len == 4)
        nu_field(indent, "connection count new", "%u", be32(value));
      else
        nu_field(indent, "connection count new", "malformed, %zu byte value", value_len);
      break;
    case 13:
      if (value_len == 4)
        nu_field(indent, "connection count echo", "%u", be32(value));
      else
        nu_field(indent, "connection count echo", "malformed, %zu byte value", value_len);
      break;
    case 14:
      if (value_len == 1)
        nu_field(indent, "alternate checksum", "algorithm %u", value[0]);
      else
        nu_field(indent, "alternate checksum", "malformed, %zu byte value", value_len);
      break;
    case 15:
      nu_field(indent, "alternate checksum data", "%zu byte%s", value_len,
               value_len == 1 ? "" : "s");
      break;
    case 19:
      nu_field(indent, "md5 signature", "%zu byte%s", value_len, value_len == 1 ? "" : "s");
      break;
    case 29:
      nu_field(indent, "authentication", "%zu byte%s", value_len, value_len == 1 ? "" : "s");
      break;
    case 34:
      nu_field(indent, "fast open cookie", "%zu byte%s", value_len,
               value_len == 1 ? "" : "s");
      break;
    default:
      nu_field(indent, "unknown option", "kind %u, %zu byte value", kind, value_len);
      break;
    }

    if (!quiet && value_len > 0 && (kind == 15 || kind == 19 || kind == 29 || kind == 34))
      nu_hexdump(stdout, value, value_len, indent + 1);

    i += option_len;
  }
}

static void dump_udp(const uint8_t *data, size_t len, const carrier *from, unsigned indent) {
  nu_section(indent, "UDP");
  if (len < 8) {
    truncated(indent + 1, "the UDP header", len, 8);
    return;
  }

  uint16_t total = be16(data + 4);
  uint16_t checksum = be16(data + 6);

  nu_field(indent + 1, "source port", "%u", be16(data));
  nu_field(indent + 1, "destination port", "%u", be16(data + 2));
  nu_field(indent + 1, "length", "%u", total);

  if (checksum == 0) {
    /* rfc0768 lets IPv4 senders skip the checksum, rfc2460 does not. */
    nu_field(indent + 1, "checksum", "0x0000 (not used)");
  } else if (from->has_pseudo && from->complete && total >= 8 && total <= len) {
    uint16_t folded = nu_fold(nu_sum(data, total, from->pseudo + total));
    nu_field(indent + 1, "checksum", "0x%04x (%s)", checksum,
             folded == 0 ? "valid" : "invalid");
  } else {
    nu_field(indent + 1, "checksum", "0x%04x (not verified)", checksum);
  }

  size_t claimed = total > 8 ? (size_t)total - 8 : 0;
  dump_payload(data + 8, len - 8, claimed, indent + 1);
}

static const char *icmp4_type_name(uint8_t type) {
  switch (type) {
  case 0: return "echo reply";
  case 3: return "destination unreachable";
  case 4: return "source quench";
  case 5: return "redirect";
  case 8: return "echo request";
  case 9: return "router advertisement";
  case 10: return "router solicitation";
  case 11: return "time exceeded";
  case 12: return "parameter problem";
  case 13: return "timestamp request";
  case 14: return "timestamp reply";
  case 17: return "address mask request";
  case 18: return "address mask reply";
  default: return "unknown";
  }
}

static void dump_icmp4(const uint8_t *data, size_t len, const carrier *from, unsigned indent) {
  nu_section(indent, "ICMP");
  if (len < 8) {
    truncated(indent + 1, "the ICMP header", len, 8);
    return;
  }

  uint8_t type = data[0];

  nu_field(indent + 1, "type", "%u (%s)", type, icmp4_type_name(type));
  nu_field(indent + 1, "code", "%u", data[1]);

  /* ICMP checksums cover the message only, there is no pseudo header. When
   * the tool starts at this layer the whole buffer is the message. */
  int complete = from->has_pseudo ? from->complete && from->claimed <= len : 1;
  size_t covered = complete && from->has_pseudo ? from->claimed : len;
  if (complete)
    nu_field(indent + 1, "checksum", "0x%04x (%s)", be16(data + 2),
             nu_checksum(data, covered) == 0 ? "valid" : "invalid");
  else
    nu_field(indent + 1, "checksum", "0x%04x (not verified)", be16(data + 2));

  if (type == 0 || type == 8) {
    nu_field(indent + 1, "identifier", "%u", be16(data + 4));
    nu_field(indent + 1, "sequence", "%u", be16(data + 6));
  }

  size_t claimed = from->claimed > 8 ? from->claimed - 8 : 0;
  dump_payload(data + 8, len - 8, claimed, indent + 1);
}

static void dump_arp(const uint8_t *data, size_t len, unsigned indent) {
  nu_section(indent, "ARP");
  if (len < 8) {
    truncated(indent + 1, "the ARP header", len, 8);
    return;
  }

  uint16_t hw_type = be16(data);
  uint16_t proto_type = be16(data + 2);
  uint8_t hw_len = data[4];
  uint8_t proto_len = data[5];
  uint16_t operation = be16(data + 6);
  static const char *operations[] = { NULL, "request", "reply", "reverse request",
                                      "reverse reply" };

  nu_field(indent + 1, "hardware type", "%u%s", hw_type,
           hw_type == 1 ? " (ethernet)" : "");
  nu_field(indent + 1, "protocol type", "0x%04x (%s)", proto_type,
           nu_ether_type_name(proto_type));
  nu_field(indent + 1, "address lengths", "hardware %u, protocol %u", hw_len, proto_len);
  nu_field(indent + 1, "operation", "%u (%s)", operation,
           operation < sizeof(operations) / sizeof(operations[0]) && operations[operation]
               ? operations[operation]
               : "unknown");

  size_t need = 8u + 2u * hw_len + 2u * proto_len;
  if (len < need) {
    truncated(indent + 1, "the ARP addresses", len, need);
    return;
  }

  if (hw_type == 1 && hw_len == 6 && proto_type == 0x0800 && proto_len == 4) {
    nu_field(indent + 1, "sender", "%s, %s", nu_mac(data + 8), nu_ipv4(data + 14));
    nu_field(indent + 1, "target", "%s, %s", nu_mac(data + 18), nu_ipv4(data + 24));
  } else if (!quiet) {
    nu_hexdump(stdout, data + 8, need - 8, indent + 1);
  }
}

static void dump_ipv4(const uint8_t *data, size_t len, unsigned indent) {
  nu_section(indent, "IPv4");
  if (len < 20) {
    truncated(indent + 1, "the IPv4 header", len, 20);
    return;
  }

  unsigned header_len = (data[0] & 0x0f) * 4u;
  uint16_t total = be16(data + 2);
  uint16_t fragment = be16(data + 6);
  unsigned offset = (fragment & 0x1fff) * 8u;
  uint8_t proto = data[9];

  nu_field(indent + 1, "version", "%u", data[0] >> 4);
  nu_field(indent + 1, "header length", "%u byte%s", header_len, header_len == 1 ? "" : "s");
  nu_field(indent + 1, "dscp", "0x%02x", data[1] >> 2);
  nu_field(indent + 1, "ecn", "%u", data[1] & 0x03);
  nu_field(indent + 1, "total length", "%u", total);
  nu_field(indent + 1, "identification", "0x%04x (%u)", be16(data + 4), be16(data + 4));
  char ip_flags[32];
  size_t ip_flags_used = 0;
  static const struct {
    uint16_t bit;
    const char *name;
  } ip_flag_names[] = { { 0x8000, "reserved" }, { 0x4000, "DF" }, { 0x2000, "MF" } };
  for (size_t i = 0; i < sizeof(ip_flag_names) / sizeof(ip_flag_names[0]); i++) {
    if (!(fragment & ip_flag_names[i].bit))
      continue;
    ip_flags_used += (size_t)snprintf(ip_flags + ip_flags_used,
                                      sizeof(ip_flags) - ip_flags_used, "%s%s",
                                      ip_flags_used ? " " : "", ip_flag_names[i].name);
  }
  nu_field(indent + 1, "flags", "%s", ip_flags_used ? ip_flags : "none");
  nu_field(indent + 1, "fragment offset", "%u", offset);
  nu_field(indent + 1, "time to live", "%u", data[8]);
  nu_field(indent + 1, "protocol", "%u (%s)", proto, nu_ip_proto_name(proto));

  if (header_len < 20 || header_len > len) {
    nu_field(indent + 1, "checksum", "0x%04x (not verified)", be16(data + 10));
    nu_field(indent + 1, "header length", "invalid, stopping here");
    return;
  }

  nu_field(indent + 1, "checksum", "0x%04x (%s)", be16(data + 10),
           nu_checksum(data, header_len) == 0 ? "valid" : "invalid");
  nu_field(indent + 1, "source", "%s", nu_ipv4(data + 12));
  nu_field(indent + 1, "destination", "%s", nu_ipv4(data + 16));

  if (header_len > 20) {
    nu_field(indent + 1, "options", "%u byte%s", header_len - 20,
             header_len - 20 == 1 ? "" : "s");
    if (!quiet)
      nu_hexdump(stdout, data + 20, header_len - 20, indent + 2);
  }

  size_t captured = len - header_len;
  size_t claimed = total > header_len ? (size_t)total - header_len : 0;

  /* Only the first fragment carries a readable upper layer header. */
  if (offset > 0) {
    nu_field(indent + 1, "fragment", "offset %u, upper layer header is elsewhere", offset);
    dump_payload(data + header_len, captured, claimed, indent + 1);
    return;
  }

  if (claimed > captured)
    nu_field(indent + 1, "captured", "%zu of %zu payload bytes", captured, claimed);

  carrier from = {
    .has_pseudo = 1,
    .pseudo = pseudo_ipv4(data + 12, data + 16, proto, 0),
    .complete = claimed > 0 && captured >= claimed,
    .claimed = claimed > 0 && captured >= claimed ? claimed : captured,
  };

  dump_upper(proto, data + header_len, captured, &from, indent + 1);
}

static void dump_ipv6(const uint8_t *data, size_t len, unsigned indent) {
  nu_section(indent, "IPv6");
  if (len < 40) {
    truncated(indent + 1, "the IPv6 header", len, 40);
    return;
  }

  uint32_t head = be32(data);
  uint16_t payload_len = be16(data + 4);
  uint8_t next = data[6];

  nu_field(indent + 1, "version", "%u", head >> 28);
  nu_field(indent + 1, "traffic class", "0x%02x", (head >> 20) & 0xff);
  nu_field(indent + 1, "flow label", "0x%05x", head & 0xfffff);
  nu_field(indent + 1, "payload length", "%u", payload_len);
  nu_field(indent + 1, "next header", "%u (%s)", next, nu_ip_proto_name(next));
  nu_field(indent + 1, "hop limit", "%u", data[7]);
  nu_field(indent + 1, "source", "%s", nu_ipv6(data + 8));
  nu_field(indent + 1, "destination", "%s", nu_ipv6(data + 24));

  size_t at = 40;
  size_t captured = len - at;
  size_t claimed = payload_len;

  /* Extension headers that share the "next header, length in eight octet
   * units" shape of rfc2460 section 4. */
  while (next == 0 || next == 43 || next == 60) {
    if (captured < 8) {
      truncated(indent + 1, "an IPv6 extension header", captured, 8);
      return;
    }
    size_t ext_len = (data[at + 1] + 1u) * 8u;
    nu_field(indent + 1, "extension header", "%u (%s), %zu byte%s", next,
             nu_ip_proto_name(next), ext_len, ext_len == 1 ? "" : "s");
    if (captured < ext_len) {
      truncated(indent + 1, "an IPv6 extension header", captured, ext_len);
      return;
    }
    next = data[at];
    at += ext_len;
    captured -= ext_len;
    claimed = claimed > ext_len ? claimed - ext_len : 0;
  }

  if (claimed > captured)
    nu_field(indent + 1, "captured", "%zu of %zu payload bytes", captured, claimed);

  carrier from = {
    .has_pseudo = 1,
    .pseudo = pseudo_ipv6(data + 8, data + 24, next, 0),
    .complete = claimed > 0 && captured >= claimed,
    .claimed = claimed > 0 && captured >= claimed ? claimed : captured,
  };

  dump_upper(next, data + at, captured, &from, indent + 1);
}

static void dump_icmp6(const uint8_t *data, size_t len, const carrier *from, unsigned indent) {
  nu_section(indent, "ICMPv6");
  if (len < 4) {
    truncated(indent + 1, "the ICMPv6 header", len, 4);
    return;
  }

  static const struct {
    uint8_t type;
    const char *name;
  } types[] = {
    { 1, "destination unreachable" }, { 2, "packet too big" }, { 3, "time exceeded" },
    { 4, "parameter problem" },       { 128, "echo request" }, { 129, "echo reply" },
    { 133, "router solicitation" },   { 134, "router advertisement" },
    { 135, "neighbor solicitation" }, { 136, "neighbor advertisement" },
  };
  const char *name = "unknown";
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    if (types[i].type == data[0])
      name = types[i].name;
  }

  nu_field(indent + 1, "type", "%u (%s)", data[0], name);
  nu_field(indent + 1, "code", "%u", data[1]);

  /* Unlike ICMP for IPv4 this checksum does cover a pseudo header. */
  if (from->has_pseudo && from->complete) {
    uint16_t folded = nu_fold(nu_sum(data, from->claimed, from->pseudo + from->claimed));
    nu_field(indent + 1, "checksum", "0x%04x (%s)", be16(data + 2),
             folded == 0 ? "valid" : "invalid");
  } else {
    nu_field(indent + 1, "checksum", "0x%04x (not verified)", be16(data + 2));
  }

  size_t claimed = from->claimed > 4 ? from->claimed - 4 : 0;
  dump_payload(data + 4, len - 4, claimed, indent + 1);
}

static void dump_upper(uint8_t proto, const uint8_t *data, size_t len, const carrier *from,
                       unsigned indent) {
  switch (proto) {
  case 1:
    dump_icmp4(data, len, from, indent);
    break;
  case 6:
    dump_tcp(data, len, from, indent);
    break;
  case 17:
    dump_udp(data, len, from, indent);
    break;
  case 58:
    dump_icmp6(data, len, from, indent);
    break;
  default:
    nu_section(indent, "%s", nu_ip_proto_name(proto));
    dump_payload(data, len, from->claimed, indent + 1);
    break;
  }
}

static void dump_ethernet(const uint8_t *data, size_t len, unsigned indent) {
  nu_section(indent, "Ethernet II");
  if (len < 14) {
    truncated(indent + 1, "the ethernet header", len, 14);
    return;
  }

  int broadcast = 1;
  for (int i = 0; i < 6; i++)
    broadcast = broadcast && data[i] == 0xff;
  nu_field(indent + 1, "destination", "%s%s", nu_mac(data),
           broadcast ? " (broadcast)" : data[0] & 0x01 ? " (multicast)" : "");
  nu_field(indent + 1, "source", "%s", nu_mac(data + 6));

  size_t at = 12;
  uint16_t ether_type = be16(data + at);
  at += 2;

  /* 802.1Q and 802.1ad insert four bytes per tag before the real type. */
  while (ether_type == 0x8100 || ether_type == 0x88a8) {
    if (len < at + 4) {
      nu_field(indent + 1, "ethertype", "0x%04x (%s)", ether_type,
               nu_ether_type_name(ether_type));
      truncated(indent + 1, "a vlan tag", len - at, 4);
      return;
    }
    uint16_t tag = be16(data + at);
    nu_field(indent + 1, ether_type == 0x8100 ? "vlan tag" : "service tag",
             "id %u, priority %u%s", tag & 0x0fff, tag >> 13,
             tag & 0x1000 ? ", drop eligible" : "");
    at += 2;
    ether_type = be16(data + at);
    at += 2;
  }

  nu_field(indent + 1, "ethertype", "0x%04x (%s)", ether_type,
           nu_ether_type_name(ether_type));

  const uint8_t *payload = data + at;
  size_t payload_len = len - at;

  switch (ether_type) {
  case 0x0800:
    dump_ipv4(payload, payload_len, indent + 1);
    break;
  case 0x0806:
  case 0x8035:
    dump_arp(payload, payload_len, indent + 1);
    break;
  case 0x86dd:
    dump_ipv6(payload, payload_len, indent + 1);
    break;
  default:
    if (ether_type <= 1500)
      nu_field(indent + 1, "note", "the field is a length, this is an 802.3 frame");
    dump_payload(payload, payload_len, payload_len, indent + 1);
    break;
  }
}

int main(int argc, char **argv) {
  const char *layer = "eth";
  int binary = 0, opt;

  while ((opt = getopt(argc, argv, "bql:h")) != -1) {
    switch (opt) {
    case 'b':
      binary = 1;
      break;
    case 'q':
      quiet = 1;
      break;
    case 'l':
      layer = optarg;
      break;
    case 'h':
      usage(stdout, argv[0]);
      return 0;
    default:
      usage(stderr, argv[0]);
      return 2;
    }
  }

  if (argc - optind > 1) {
    usage(stderr, argv[0]);
    return 2;
  }

  if (strcmp(layer, "eth") != 0 && strcmp(layer, "ip") != 0 && strcmp(layer, "tcp") != 0 &&
      strcmp(layer, "udp") != 0 && strcmp(layer, "icmp") != 0) {
    fprintf(stderr, "%s: unknown layer '%s'\n", argv[0], layer);
    return 2;
  }

  const char *path = optind < argc ? argv[optind] : NULL;

  uint8_t *buf = malloc(NU_MAX_FRAME);
  if (!buf) {
    fprintf(stderr, "%s: out of memory\n", argv[0]);
    return 2;
  }

  ssize_t len = nu_load(path, binary, buf, NU_MAX_FRAME);
  if (len < 0) {
    fprintf(stderr, "%s: %s: %s\n", argv[0], path ? path : "standard input",
            errno == EINVAL ? "input is not valid hex" : strerror(errno));
    free(buf);
    return 2;
  }

  if (len == 0) {
    fprintf(stderr, "%s: empty input\n", argv[0]);
    free(buf);
    return 2;
  }

  nu_field(0, "frame length", "%zd byte%s", len, len == 1 ? "" : "s");

  if (strcmp(layer, "eth") == 0) {
    dump_ethernet(buf, (size_t)len, 0);
  } else if (strcmp(layer, "ip") == 0) {
    /* The version nibble tells the two network layers apart. */
    if ((buf[0] >> 4) == 6)
      dump_ipv6(buf, (size_t)len, 0);
    else
      dump_ipv4(buf, (size_t)len, 0);
  } else if (strcmp(layer, "tcp") == 0) {
    carrier from = no_carrier;
    from.claimed = (size_t)len;
    dump_tcp(buf, (size_t)len, &from, 0);
  } else if (strcmp(layer, "udp") == 0) {
    carrier from = no_carrier;
    from.claimed = (size_t)len;
    dump_udp(buf, (size_t)len, &from, 0);
  } else {
    carrier from = no_carrier;
    from.claimed = (size_t)len;
    dump_icmp4(buf, (size_t)len, &from, 0);
  }

  free(buf);

  return 0;
}
