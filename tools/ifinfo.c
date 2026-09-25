/*
 * netifinfo - lists the network interfaces of the host with the details the
 * rest of the library needs: the index an XDP program is attached to, the
 * flags, the mtu and the addresses.
 *
 * detector/loader.c carries a hard coded list of interface names. Running
 * this tool with -x prints the names that are worth attaching to on the
 * current host, which is the list that belongs in such a loader.
 */
#include "netutil.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(FILE *out, const char *name) {
  fprintf(out,
          "usage: %s [-x] [-h] [interface ...]\n"
          "\n"
          "Prints the interfaces of this host, or only the ones named.\n"
          "\n"
          "  -x   print just the names an XDP program can attach to,\n"
          "       one per line: up, running and not the loopback\n"
          "  -h   print this help\n",
          name);
}

/* Number of leading one bits of a netmask, its prefix length. */
static unsigned prefix_length(const uint8_t *mask, size_t len) {
  unsigned bits = 0;

  for (size_t i = 0; i < len; i++) {
    uint8_t byte = mask[i];
    while (byte & 0x80) {
      bits++;
      byte = (uint8_t)(byte << 1);
    }
    if (mask[i] != 0xff)
      break;
  }

  return bits;
}

static const char *flag_text(unsigned int flags) {
  static const struct {
    unsigned int bit;
    const char *name;
  } names[] = {
    { IFF_UP, "UP" },                   { IFF_BROADCAST, "BROADCAST" },
    { IFF_LOOPBACK, "LOOPBACK" },       { IFF_POINTOPOINT, "POINTOPOINT" },
    { IFF_RUNNING, "RUNNING" },         { IFF_NOARP, "NOARP" },
    { IFF_PROMISC, "PROMISC" },         { IFF_ALLMULTI, "ALLMULTI" },
    { IFF_MULTICAST, "MULTICAST" },     { IFF_DEBUG, "DEBUG" },
  };
  static char buf[160];
  size_t used = 0;

  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (!(flags & names[i].bit))
      continue;
    used += (size_t)snprintf(buf + used, sizeof(buf) - used, "%s%s", used ? " " : "",
                             names[i].name);
  }

  if (used == 0)
    snprintf(buf, sizeof(buf), "none");

  return buf;
}

/* An interface an XDP program can usefully be attached to. */
static int attachable(unsigned int flags) {
  return (flags & IFF_UP) && (flags & IFF_RUNNING) && !(flags & IFF_LOOPBACK);
}

static int wanted(const char *name, int argc, char **argv, int first) {
  if (first >= argc)
    return 1;

  for (int i = first; i < argc; i++) {
    if (strcmp(name, argv[i]) == 0)
      return 1;
  }

  return 0;
}

static int mtu_of(int sock, const char *name) {
  struct ifreq request;

  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
  if (sock < 0 || ioctl(sock, SIOCGIFMTU, &request) < 0)
    return -1;

  return request.ifr_mtu;
}

static void report(const struct ifaddrs *list, const char *name, int sock) {
  unsigned int flags = 0;

  nu_section(0, "%s", name);

  for (const struct ifaddrs *it = list; it; it = it->ifa_next) {
    if (strcmp(it->ifa_name, name) == 0) {
      flags = it->ifa_flags;
      break;
    }
  }

  unsigned index = if_nametoindex(name);
  if (index > 0)
    nu_field(1, "index", "%u", index);
  nu_field(1, "flags", "0x%x (%s)", flags, flag_text(flags));

  int mtu = mtu_of(sock, name);
  if (mtu >= 0)
    nu_field(1, "mtu", "%d", mtu);

  nu_field(1, "xdp target", "%s", attachable(flags) ? "yes" : "no");

  for (const struct ifaddrs *it = list; it; it = it->ifa_next) {
    if (strcmp(it->ifa_name, name) != 0 || !it->ifa_addr)
      continue;

    switch (it->ifa_addr->sa_family) {
    case AF_PACKET: {
      const struct sockaddr_ll *ll = (const struct sockaddr_ll *)it->ifa_addr;
      if (ll->sll_halen == 6)
        nu_field(1, "hardware", "%s", nu_mac(ll->sll_addr));
      break;
    }
    case AF_INET: {
      const struct sockaddr_in *in = (const struct sockaddr_in *)it->ifa_addr;
      const uint8_t *addr = (const uint8_t *)&in->sin_addr;
      unsigned bits = 32;
      if (it->ifa_netmask) {
        const struct sockaddr_in *mask = (const struct sockaddr_in *)it->ifa_netmask;
        bits = prefix_length((const uint8_t *)&mask->sin_addr, 4);
      }
      nu_field(1, "inet", "%s/%u", nu_ipv4(addr), bits);
      break;
    }
    case AF_INET6: {
      const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)it->ifa_addr;
      const uint8_t *addr = (const uint8_t *)&in6->sin6_addr;
      unsigned bits = 128;
      if (it->ifa_netmask) {
        const struct sockaddr_in6 *mask = (const struct sockaddr_in6 *)it->ifa_netmask;
        bits = prefix_length((const uint8_t *)&mask->sin6_addr, 16);
      }
      if (in6->sin6_scope_id)
        nu_field(1, "inet6", "%s%%%u/%u", nu_ipv6(addr), in6->sin6_scope_id, bits);
      else
        nu_field(1, "inet6", "%s/%u", nu_ipv6(addr), bits);
      break;
    }
    default:
      break;
    }
  }
}

int main(int argc, char **argv) {
  int names_only = 0, opt;

  while ((opt = getopt(argc, argv, "xh")) != -1) {
    switch (opt) {
    case 'x':
      names_only = 1;
      break;
    case 'h':
      usage(stdout, argv[0]);
      return 0;
    default:
      usage(stderr, argv[0]);
      return 2;
    }
  }

  struct ifaddrs *list;
  if (getifaddrs(&list) < 0) {
    fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
    return 2;
  }

  /* Only used for the mtu, a failure here costs one field and nothing else. */
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  /* getifaddrs() reports one entry per address, so the names repeat. */
  const char *seen[256];
  size_t seen_count = 0;
  int found = 0;

  for (const struct ifaddrs *it = list; it; it = it->ifa_next) {
    int duplicate = 0;
    for (size_t i = 0; i < seen_count; i++)
      duplicate = duplicate || strcmp(seen[i], it->ifa_name) == 0;
    if (duplicate)
      continue;
    if (seen_count < sizeof(seen) / sizeof(seen[0]))
      seen[seen_count++] = it->ifa_name;

    if (!wanted(it->ifa_name, argc, argv, optind))
      continue;
    found = 1;

    if (names_only) {
      if (attachable(it->ifa_flags))
        printf("%s\n", it->ifa_name);
      continue;
    }

    report(list, it->ifa_name, sock);
  }

  if (!found && optind < argc)
    fprintf(stderr, "%s: no such interface\n", argv[0]);

  if (sock >= 0)
    close(sock);
  freeifaddrs(list);

  return found ? 0 : 1;
}
