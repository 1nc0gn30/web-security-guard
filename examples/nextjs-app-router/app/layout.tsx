import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Script from 'next/script';
import React from 'react';

export const metadata: Metadata = {
  title: 'Next.js App Router with CSP Nonce Protection',
  description: 'Production-ready Next.js 14/15 application secured by Web Security Guard',
};

/**
 * Root Layout Component
 *
 * Demonstrates extracting the per-request cryptographic nonce injected by middleware.ts
 * and safely binding it to Next.js <Script> tags and inline styles.
 */
export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Read the 'x-nonce' request header injected by our edge middleware
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') || undefined;

  return (
    <html lang="en">
      <head>
        {/* Meta viewport and charset */}
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body>
        <main>{children}</main>

        {/* Example inline script protected by the cryptographically generated nonce */}
        <Script
          id="analytics-init"
          strategy="afterInteractive"
          nonce={nonce}
          dangerouslySetInnerHTML={{
            __html: `
              window.__SECURITY_INITIALIZED = true;
              console.log("🛡️ Page loaded with valid CSP Level 3 nonce protection.");
            `,
          }}
        />
      </body>
    </html>
  );
}
