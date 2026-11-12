import { isIP } from 'node:net';

/**
 * Expands an IPv6 literal (no zone id) into its 8 hextets, or null if it cannot be parsed.
 * Handles `::` compression and an embedded dotted IPv4 tail (`::ffff:1.2.3.4`).
 */
function expandIPv6(address: string): number[] | null {
  let text = address;
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = tail.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const [a, b, c, d] = octets as [number, number, number, number];
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string): string[] => (s === '' ? [] : s.split(':'));
  const head = parse(halves[0] ?? '');
  const rest = halves.length === 2 ? parse(halves[1] ?? '') : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  const values = groups.map((g) => parseInt(g, 16));
  if (values.length !== 8 || values.some((v) => Number.isNaN(v))) return null;
  return values;
}

/**
 * Bucket key for per-client rate limits.
 *
 * - An IPv6 client normally controls a whole /64, so keying on the full address would let it
 *   rotate through 2^64 addresses and never hit a limit; we key on the /64 prefix instead.
 * - IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is the same client as `1.2.3.4` (dual-stack sockets
 *   report this form), so it is folded into the IPv4 bucket rather than getting a second one.
 * - Anything that is not a valid IP collapses into 'unknown' rather than letting an arbitrary
 *   string choose its own bucket key.
 */
export function rateLimitSubject(ip: string | undefined): string {
  if (!ip) return 'unknown';
  const address = ip.split('%')[0] ?? '';
  const family = isIP(address);
  if (family === 4) return address;
  if (family !== 6) return 'unknown';

  const hextets = expandIPv6(address);
  if (!hextets) return 'unknown';

  const [h0, h1, h2, h3, h4, h5, h6, h7] = hextets as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0xffff) {
    return `${h6 >> 8}.${h6 & 0xff}.${h7 >> 8}.${h7 & 0xff}`;
  }
  return `${[h0, h1, h2, h3].map((h) => h.toString(16)).join(':')}::/64`;
}
