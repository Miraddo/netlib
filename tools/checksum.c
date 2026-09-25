/*
 * netchecksum - computes and verifies the internet checksum of RFC 1071.
 *
 * The same one byte at a time algorithm is used by IPv4, ICMP, TCP and UDP,
 * so the tool doubles as a way to check a header that a capture or a hand
 * written test frame carries.
 */
#include "netutil.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *out, const char *name) {
  fprintf(out,
          "usage: %s [-b] [-c] [-v] [-s sum] [file]\n"
          "\n"
          "Reads a buffer and prints its internet checksum, RFC 1071.\n"
          "Without a file the buffer is read from standard input.\n"
          "\n"
          "  -b       read raw binary instead of hex text\n"
          "  -c       verify instead of compute, exits 1 when the checksum is wrong\n"
          "  -s sum   seed with a partial sum, for example a pseudo header\n"
          "  -v       also print the buffer\n"
          "  -h       print this help\n",
          name);
}

int main(int argc, char **argv) {
  int binary = 0, verify = 0, verbose = 0, opt;
  uint32_t seed = 0;

  while ((opt = getopt(argc, argv, "bcvs:h")) != -1) {
    switch (opt) {
    case 'b':
      binary = 1;
      break;
    case 'c':
      verify = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 's': {
      char *end;
      unsigned long value = strtoul(optarg, &end, 0);
      if (*optarg == '\0' || *end != '\0' || value > 0xffffffffUL) {
        fprintf(stderr, "%s: bad seed '%s'\n", argv[0], optarg);
        return 2;
      }
      seed = (uint32_t)value;
      break;
    }
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

  uint16_t checksum = nu_fold(nu_sum(buf, (size_t)len, seed));

  if (verbose)
    nu_hexdump(stdout, buf, (size_t)len, 0);

  nu_field(0, "length", "%zd byte%s", len, len == 1 ? "" : "s");
  if (seed)
    nu_field(0, "seed", "0x%08x", seed);

  int status = 0;
  if (verify) {
    /* Data that already carries a correct checksum sums up to 0xffff, which
     * the complement in nu_fold() turns into 0. */
    nu_field(0, "verify", "%s", checksum == 0 ? "valid" : "invalid");
    if (checksum != 0) {
      nu_field(0, "difference", "0x%04x", checksum);
      status = 1;
    }
  } else {
    nu_field(0, "checksum", "0x%04x (%u)", checksum, checksum);
  }

  free(buf);

  return status;
}
