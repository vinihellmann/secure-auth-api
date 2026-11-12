import { rateLimitSubject } from '../../src/http/client-ip';

describe('rateLimitSubject', () => {
  it('returns IPv4 unchanged', () => {
    expect(rateLimitSubject('203.0.113.7')).toBe('203.0.113.7');
  });

  it('maps IPv4-mapped IPv6 to the IPv4 bucket', () => {
    expect(rateLimitSubject('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(rateLimitSubject('::FFFF:203.0.113.7')).toBe('203.0.113.7');
    expect(rateLimitSubject('::ffff:cb00:7107')).toBe('203.0.113.7');
    expect(rateLimitSubject('0:0:0:0:0:ffff:1.2.3.4')).toBe('1.2.3.4');
  });

  it('returns the /64 prefix for IPv6', () => {
    expect(rateLimitSubject('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
  });

  it('puts every address in the same /64 in one bucket', () => {
    const a = rateLimitSubject('2001:db8:1:2::1');
    expect(rateLimitSubject('2001:db8:1:2:ffff:ffff:ffff:ffff')).toBe(a);
    expect(rateLimitSubject('2001:0db8:0001:0002:0000:0000:0000:0001')).toBe(a);
    expect(rateLimitSubject('2001:db8:1:3::1')).not.toBe(a);
  });

  it('handles compressed forms', () => {
    expect(rateLimitSubject('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(rateLimitSubject('::1')).toBe('0:0:0:0::/64');
    expect(rateLimitSubject('::')).toBe('0:0:0:0::/64');
    expect(rateLimitSubject('2001:db8:1:2::')).toBe('2001:db8:1:2::/64');
  });

  it('normalises case and leading zeros', () => {
    expect(rateLimitSubject('2001:DB8:0001:00AB::1')).toBe('2001:db8:1:ab::/64');
  });

  it('ignores zone ids', () => {
    expect(rateLimitSubject('fe80::1%eth0')).toBe('fe80:0:0:0::/64');
  });

  it('returns unknown for empty or invalid input', () => {
    expect(rateLimitSubject(undefined)).toBe('unknown');
    expect(rateLimitSubject('')).toBe('unknown');
    expect(rateLimitSubject('not-an-ip')).toBe('unknown');
    expect(rateLimitSubject('1.2.3')).toBe('unknown');
    expect(rateLimitSubject('2001:db8::1::2')).toBe('unknown');
  });
});
