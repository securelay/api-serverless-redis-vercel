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
import { cdnURL, hash, sign } from './api/_utils.js';

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

const bodyLimit = parseInt(process.env.BODYLIMIT);

const ratelimit = new Ratelimit({
  redis: new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL_CACHE,
    token: process.env.UPSTASH_REDIS_REST_TOKEN_CACHE
  }),
  ephemeralCache: false,
  analytics: false,
  limiter: Ratelimit.slidingWindow(parseInt(process.env.RATELIMIT), process.env.RATELIMIT_WINDOW + ' s'),
  prefix: 'rl:',
  enableProtection: true
});

const allowedMethods = ['HEAD', 'GET', 'POST', 'PATCH', 'DELETE'];

const statusCodes = {
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  405: 'Method Not Allowed',
  417: 'Expectation Failed',
  429: 'Too Many Requests'
};

// Match given URL path to given pattern and extract given parameters.
// Returns null if no match, so that one can use ?? (nullish) operator with the returned value
// Returns {parameter: <match>, ...} otherwise.
// Parameter syntax: Parameters start with : and optional parameters end with ?.
// Pattern example: /public/:key/:channel?
// Guarantees non-empty strings as values for non-optional patterns.
// Note: Doesn't use regexp for performance.
// See also: https://www.npmjs.com/package/path-to-regexp
// TODO: Support wildcard/catch-all parameters represented with a trailing *, e.g. :all*
export function pathMatch (path, pattern) {
  const arrayFromPattern = pattern.split('/');
  const arrayFromPath = path.split('/');
  const patLength = arrayFromPattern.length;
  // arrayFromPath may be shorter than patLength if optional parameters are present
  if (arrayFromPath.length > patLength) return null;
  const obj = {};
  for (let i = 0; i < patLength; i++) {
    const patternSlug = arrayFromPattern[i];
    const pathSlug = arrayFromPath[i];
    const isParamater = patternSlug.startsWith(':');
    const isOptional = isParamater && patternSlug.endsWith('?');
    let paramName;
    switch (true) {
      case isOptional:
        paramName = patternSlug.slice(0,-1);
        // Fall-through to next case
      case isParamater:
        // pathSlug can only be empty string or undefined if corresponding parameter is optional
        if (!(isOptional || pathSlug)) return null;
        paramName = (paramName ?? patternSlug).substring(1); // pathName is undefined if isOptional == false
        obj[paramName] = pathSlug;
      case patternSlug === pathSlug:
        break;
      default:
        return null;
    }
  }
  return obj;
}

// Returns Response object with JSON body containing error details for given statusCode
// message parameter is optional
function prepResponse (statusCode, message, { cache, redirect, cookies } = {}) {
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

// This is the entry point to middleware, the default export that Vercel invokes
// Performs basic validation and limiting
// Returns a Response object or Promise that resolves to a Response
// Calling next() actually returns a Response with added header 'x-middleware-next'
// Ref: @vercel/edge source - https://www.npmjs.com/package/@vercel/edge?activeTab=code
// Note: To optimize, avoid calling the rate-limiter database whenever possible
export default async function middleware (request) {
  const requestPath = new URL(request.url).pathname;

  // Block requests with Expect headers
  if (request.headers.has('expect')) return prepResponse(417, 'Expect header is not allowed');

  // Detect a pipe request to let it have any Content-Type and Length, including `Transfer-Encoding: chunked` header
  const isPiped = requestPath.endsWith('.pipe');

  // Block unallowed methods and chunked transfer if not pipe
  if (!isPiped) {
    if (allowedMethods.includes(request.method.toUpperCase()) === false) {
      return prepResponse(405, `Method: ${request.method}, is not allowed`);
    }
    if (request.headers.get('transfer-encoding')?.toLowerCase()?.includes('chunked')) {
      return prepResponse(400, 'Provide content-length header instead of chunked transfer');
    }
    
    // Redirect to CDN link if path is /public/:publicKey
    if (request.method.toUpperCase() === 'GET' || request.method.toUpperCase() === 'HEAD') {
      const { publicKey } = pathMatch(requestPath, '/public/:publicKey') ?? {};
      if (publicKey) return Response.redirect(await cdnURL(publicKey), 301)
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
        return prepResponse(400, `Content-Length: ${contentLength}, is not within ${bodyLimit}`);
      } else {
        break;
      }
    default:
      return prepResponse(400, `Content-Type: '${contentType}', is not allowed`);
  }

  // Ratelimiting by ip is too restrictive: may block users accessing internet from the same router
  const ratelimitBy = await hash(request.method + requestPath + ipAddress(request));

  const { success, reset } = await ratelimit.limit(ratelimitBy);

  if (success) {
    return next();
  } else {
    return prepResponse(429, `Try after ${(reset - Date.now()) / 1000} seconds`);
  }
}
