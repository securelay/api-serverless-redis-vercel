/*
Refs:
https://vercel.com/guides/rate-limiting-edge-middleware-vercel-kv
https://vercel.com/docs/functions/edge-middleware/middleware-api
https://upstash.com/docs/redis/sdks/ratelimit-ts/features#caching
https://upstash.com/docs/redis/sdks/ratelimit-ts/methods#limit
https://upstash.com/docs/redis/sdks/ratelimit-ts/traffic-protection
https://github.com/upstash/ratelimit-js/issues/122
*/
import { ipAddress } from '@vercel/functions';
import { next } from '@vercel/edge';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import { cdnURL } from './api/_utils.js';

// Middleware runs for the following paths only.
// This avoids unnecessary invocations and ratelimit calls which would otherwise count towards Vercel pricing.
// Note: paths with trailing slashes are not allowed by using regexp: $
// Such paths hit vercel.json (with `trailingSlash: false`) directly and get redirected automatically!
export const config = {
  matcher: [
    '/keys($)',
    '/(public|private|keys)/([\\w-]+$)',
    '/(public|private)/([\\w-]+)/([\\w-]+$)',
    '/(public|private)/([\\w-]+).pipe($)',
    '/(public|private)/([\\w-]+).kv($)',
    '/(public|private)/([\\w-]+).kv/(.*)'
  ]
}

const middlewareSig = process.env.SECRET; // Secret known to middleware only
const bodyLimit = parseInt(process.env.BODYLIMIT);

const cache = new Map(); // must be outside of your serverless function handler

const ratelimit = new Ratelimit({
  redis: new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL_CACHE,
    token: process.env.UPSTASH_REDIS_REST_TOKEN_CACHE
  }),
  ephemeralCache: cache,
  analytics: false,
  limiter: Ratelimit.slidingWindow(parseInt(process.env.RATELIMIT), process.env.RATELIMIT_WINDOW + ' s'),
  prefix: 'rl:',
  enableProtection: true
});

const allowedMethods = ['HEAD', 'GET', 'POST', 'PATCH', 'DELETE'];

const statusCodes = {
  400: 'Bad Request',
  405: 'Method Not Allowed',
  417: 'Expectation Failed',
  429: 'Too Many Requests'
};

// Returns Response object with JSON body containing error details for given statusCode
// message parameter is optional
function errorResponse (statusCode, message) {
  const statusText = statusCodes[statusCode];
  const supportedMethods = allowedMethods.join(',');
  return Response.json(
    { message: message ?? statusText, error: statusText, statusCode },
    {
      status: statusCode,
      statusText,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': supportedMethods,
        Allow: supportedMethods
      }
    }
  );
}

// Returns a response from the backend (serverless-function) to the piped request modified to have no body.
// Prevents Fastify in the backend from parsing the original request.body unnecessarily.
// May not be needed when Fastify dependency is removed from the backend.
async function processPipe (request) {
  // No need to worry with GET/HEAD requests as Fastify at backend won't parse content for these methods
  if (request.method.match(/(GET|HEAD)/gi)) return next();
  return fetch(request.url, {
    method: request.method,
    headers: { 'x-middleware-auth': middlewareSig },
    redirect: 'manual'
  });
}

// This is the entry point to middleware, the default export that Vercel invokes
// Performs basic validation and limiting
// Returns a Response object or Promise that resolves to a Response
// Calling next() actually returns a Response with added header 'x-middleware-next'
// Ref: @vercel/edge source - https://www.npmjs.com/package/@vercel/edge?activeTab=code
// Note: To optimize, avoid calling the rate-limiter database whenever possible
export default async function middleware (request) {
  const requestPath = new URL(request.url).pathname;

  // Block requests with Expect headers
  if (request.headers.has('expect')) return errorResponse(417, 'Expect header is not allowed');

  // Detect a pipe request to let it have any Content-Type and Length, including `Transfer-Encoding: chunked` header
  const isPiped = requestPath.endsWith('.pipe');

  // Block unallowed methods and chunked transfer if not pipe
  if (!isPiped) {
    if (allowedMethods.includes(request.method.toUpperCase()) === false) {
      return errorResponse(405, `Method: ${request.method}, is not allowed`);
    }
    if (request.headers.get('transfer-encoding')?.toLowerCase()?.includes('chunked')) {
      return errorResponse(400, 'Provide content-length header instead of chunked transfer');
    }
    if (request.method.toUpperCase() === 'GET') {
      const [, keyType, key] = new RegExp(config.matcher[1]).exec(requestPath) ?? [];
      if (keyType === 'public' && key) return Response.redirect(await cdnURL(key), 301)
    }
  }

  const contentType = request.headers.get('content-type') ?? '';
  const contentLength = parseInt(request.headers.get('content-length') ?? 0);
  // Absent content-length is as good as 0, as Transfer-Encoding: chunked is not allowed

  switch (true) {
    case isPiped:
      break; // Allowed to have any Content-Type and Length, including `Transfer-Encoding: chunked` header
    case contentLength === 0:
      break; // Doesn't matter what the content-type is as it wont be parsed
    case contentType.includes('application/json'):
    case contentType.includes('application/x-www-form-urlencoded'):
    case contentType.includes('text/plain'):
    case contentType.includes('text/html'):
      if (contentLength > bodyLimit) {
        return errorResponse(400, `Content-Length: ${contentLength}, is not within ${bodyLimit}`);
      } else {
        break;
      }
    default:
      return errorResponse(400, `Content-Type: '${contentType}', is not allowed`);
  }

  // If one invocation of this middleware modifies the Request and resends,
  // another invocation of this middleware will intercept it before it reaches the backend.
  // The following flag tells the latter invocation that it need not re-process the request.
  const isFromMiddleware = request.headers.get('x-middleware-auth') === middlewareSig;

  // Ratelimiting by ip is too restrictive: may block users accessing internet from the same router
  const ratelimitBy = [
    request.method,
    requestPath,
    ipAddress(request)
  ].join('@');

  // For requests from middleware, no rate-limiting is necessary
  const { success, reset } = isFromMiddleware ? { success: true, reset: 0 } : await ratelimit.limit(ratelimitBy);

  if (success) {
    switch (true) {
      case isPiped:
        if (!isFromMiddleware) return processPipe(request);
      default:
        return next();
    }
  } else {
    return errorResponse(429, `Try after ${(reset - Date.now()) / 1000} seconds`);
  }
}
