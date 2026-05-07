/**
 * Drop-in replacement for ~/workplace-interview-agent/next.config.ts
 *
 * Adds a host-based redirect sending all traffic from
 *   findmypurpose.clarity360hq.com
 * to
 *   engagingpurpose.com
 *
 * If your existing nextConfig has other keys not shown here, merge the
 * `redirects` function in rather than replacing the whole object.
 */

import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  async redirects() {
    return [
      {
        source: '/:path*',
        has: [{ type: 'host', value: 'findmypurpose.clarity360hq.com' }],
        destination: 'https://engagingpurpose.com/:path*',
        permanent: false,
      },
    ];
  },
  transpilePackages: [
    'react-markdown',
    'remark-gfm',
    'remark-parse',
    'remark-rehype',
    'unified',
    'bail',
    'is-plain-obj',
    'trough',
    'vfile',
    'vfile-message',
    'unist-util-stringify-position',
    'unist-util-visit',
    'unist-util-visit-parents',
    'unist-util-is',
    'mdast-util-from-markdown',
    'mdast-util-to-hast',
    'mdast-util-gfm',
    'hast-util-to-jsx-runtime',
    'hast-util-whitespace',
    'property-information',
    'space-separated-tokens',
    'comma-separated-tokens',
    'devlop',
    'decode-named-character-reference',
  ],
};

export default nextConfig;
