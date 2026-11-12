/**
 * Client metadata captured at the HTTP edge and passed down to services,
 * so services stay free of Express types.
 */
export interface RequestContext {
  ip: string | null;
  userAgent: string | null;
}
