import { NextRequest, NextResponse } from 'next/server';

/**
 * Next.js 14/15 App Router Security Middleware
 *
 * Implements Google Security best practices:
 * 1. Generates a cryptographically random, per-request base64 nonce.
 * 2. Emits a Level 3 Content Security Policy (CSP) with 'strict-dynamic'.
 * 3. Propagates the nonce via 'x-nonce' request header to Server Components.
 * 4. Injects complete defense-in-depth security headers into the response.
 */
export function middleware(request: NextRequest) {
  // 1. Generate 128-bit cryptographic nonce
  const nonceBuffer = new Uint8Array(16);
  crypto.getRandomValues(nonceBuffer);
  const nonce = Buffer.from(nonceBuffer).toString('base64');

  // 2. Formulate strict Content-Security-Policy Level 3
  const isDev = process.env.NODE_ENV === 'development';
  
  // Note: in development, Next.js fast-refresh / HMR requires 'unsafe-eval'
  const scriptSrcDirectives = [
    "'self'",
    `'nonce-${nonce}'`,
    "'strict-dynamic'",
    ...(isDev ? ["'unsafe-eval'"] : []),
  ].join(' ');

  const cspHeaderValue = [
    "default-src 'self'",
    `script-src ${scriptSrcDirectives}`,
    `style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com`,
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https: wss:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
  ].join('; ') + ';';

  // 3. Set request headers to forward nonce to React Server Components
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeaderValue);

  // 4. Create Next.js response with mutated request headers
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  // 5. Apply hardened response headers
  response.headers.set('Content-Security-Policy', cspHeaderValue);
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()'
  );
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  response.headers.set('Cross-Origin-Resource-Policy', 'same-origin');

  return response;
}

/**
 * Route Matcher Configuration
 * Excludes Next.js internal static assets, static images, and favicon.
 */
export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
