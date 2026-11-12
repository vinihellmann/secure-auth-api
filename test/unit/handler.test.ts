import type { Request, Response } from 'express';
import { authed, noStore } from '../../src/http/handler';

describe('authed', () => {
  const res = {} as Response;

  it('throws 401 when req.auth is missing', () => {
    const fn = jest.fn();
    expect(() => authed(fn)({} as Request, res, jest.fn())).toThrow(/authentication/i);
    expect(fn).not.toHaveBeenCalled();
  });

  it('calls the handler with the request', async () => {
    const fn = jest.fn().mockResolvedValue(undefined);
    const req = { auth: { userId: 'u', sessionId: 's', roles: [] } } as unknown as Request;
    await authed(fn)(req, res, jest.fn());
    expect(fn).toHaveBeenCalledWith(req, res);
  });
});

describe('noStore', () => {
  it('sets Cache-Control and returns the response', () => {
    const res = { set: jest.fn().mockReturnThis() } as unknown as Response;
    expect(noStore(res)).toBe(res);
    expect(res.set).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });
});
