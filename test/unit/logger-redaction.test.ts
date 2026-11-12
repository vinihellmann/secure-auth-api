import { Writable } from 'node:stream';
import winston from 'winston';
import {
  REDACTED,
  isSensitiveEntry,
  isSensitiveKey,
  redact,
  redactFormat,
} from '../../src/infra/logger';

describe('isSensitiveKey', () => {
  it.each([
    'password',
    'Passwd',
    'secret',
    'token',
    'accessToken',
    'refreshToken',
    'mfaToken',
    'newPassword',
    'clientSecret',
    'Authorization',
    'cookie',
    'recoveryCode',
    'OTP',
  ])('redacts %s', (k) => expect(isSensitiveKey(k)).toBe(true));

  it.each([
    'message',
    'requestId',
    'status',
    'statusCode',
    'errorCode',
    'durationMs',
    'tokenType',
    'userId',
    'sessionId',
  ])('keeps %s', (k) => expect(isSensitiveKey(k)).toBe(false));
});

describe('isSensitiveEntry (bare code)', () => {
  it.each(['123456', '12345678', 'ABCDE-FGH23', 'abcde-fgh23', 'ABCDEFGH23'])(
    'redacts OTP-like code %s',
    (v) => expect(isSensitiveEntry('code', v)).toBe(true),
  );

  it.each([['ECONNREFUSED'], ['ECONNRESET'], ['23505'], ['ERR_HTTP_HEADERS_SENT'], [401]])(
    'keeps diagnostic code %s',
    (v) => expect(isSensitiveEntry('code', v)).toBe(false),
  );
});

describe('redact', () => {
  it('redacts nested keys and arrays, keeps others', () => {
    const input = {
      requestId: 'r1',
      statusCode: 401,
      body: { email: 'a@b.c', password: 'hunter2', list: [{ refreshToken: 'x', ok: 1 }] },
    };
    expect(redact(input)).toEqual({
      requestId: 'r1',
      statusCode: 401,
      body: { email: 'a@b.c', password: REDACTED, list: [{ refreshToken: REDACTED, ok: 1 }] },
    });
  });

  it('does not mutate the input', () => {
    const input = { a: { password: 'p' } };
    redact(input);
    expect(input.a.password).toBe('p');
  });

  it('handles cycles', () => {
    const a: Record<string, unknown> = { name: 'a' };
    a.self = a;
    expect(redact(a)).toEqual({ name: 'a', self: '[Circular]' });
  });

  it('caps depth', () => {
    let deep: Record<string, unknown> = { password: 'p' };
    for (let i = 0; i < 20; i++) deep = { n: deep };
    expect(JSON.stringify(redact(deep))).toContain('[Truncated]');
  });

  it('keeps Error message and stack', () => {
    const err = Object.assign(new Error('boom'), { token: 't', extra: 1 });
    const out = redact({ err }).err as unknown as Record<string, unknown>;
    expect(out.message).toBe('boom');
    expect(typeof out.stack).toBe('string');
    expect(out.token).toBe(REDACTED);
    expect(out.extra).toBe(1);
  });

  it('leaves Dates alone', () => {
    const d = new Date(0);
    expect(redact({ d }).d).toBe(d);
  });
});

describe('redactFormat', () => {
  it('preserves winston symbol keys and redacts metadata', () => {
    const lines: string[] = [];
    const logger = winston.createLogger({
      format: winston.format.combine(redactFormat(), winston.format.json()),
      transports: [
        new winston.transports.Stream({
          stream: new Writable({
            write(chunk: Buffer, _enc, cb) {
              lines.push(chunk.toString());
              cb();
            },
          }),
        }),
      ],
    });
    logger.info('login', { password: 'p', requestId: 'r', nested: { accessToken: 't' } });
    const parsed = JSON.parse(lines[0] ?? '{}') as Record<string, unknown>;
    expect(parsed).toMatchObject({
      level: 'info',
      message: 'login',
      password: REDACTED,
      requestId: 'r',
      nested: { accessToken: REDACTED },
    });
  });
});
