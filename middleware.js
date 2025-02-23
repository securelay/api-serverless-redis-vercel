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

const middlewareSig = process.env.SECRET; // Secret known to middleware only
const bodyLimit = parseInt(process.env.BODYLIMIT);

const cache = new Map(); // must be outside of your serverless function handler

const ratelimit = new Ratelimit({
  redis: new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL_CACHE,
    token: process.env.UPSTASH_REDIS_REST_TOKEN_CACHE,
  }),
  ephemeralCache: cache,
  analytics: false,
  limiter: Ratelimit.slidingWindow(parseInt(process.env.RATELIMIT), process.env.RATELIMIT_WINDOW + ' s'),
  prefix: "rl:",
  enableProtection: true
})

// Returns a response from the backend (serverless-function) to the piped request modified to have no body.
// Prevents Fastify in the backend from parsing the original request.body unnecessarily.
// May not be needed when Fastify dependency is removed from the backend.
async function processPipe(request) {
  // No need to worry with GET/HEAD requests as Fastify at backend won't parse content for these methods
  if (request.method.match(/(GET|HEAD)/gi)) return next();
  return fetch(request.url, {
    method: request.method,
    headers: { 'x-middleware' : middlewareSig },
    redirect: 'manual'
  });
}

// Performs basic validation and limiting
// Returns a Response object or Promise that resolves to a Response
// Calling next() actually returns a Response with added header 'x-middleware-next'
// Ref: @vercel/edge source - https://www.npmjs.com/package/@vercel/edge?activeTab=code
export default async function middleware(request) {
  // Block requests with Expect headers
  if (request.headers.has('expect')) return Response.json(
    { message: 'Expect header is not allowed', error: "Expectation Failed", statusCode: 417 },
    {
      status: 417,
      statusText: "Expectation Failed",
      headers: {"Access-Control-Allow-Origin":"*"}
    }
  )
  
  const contentType = request.headers.get('content-type') ?? '';
  const isNotChunked = !(request.headers.get('transfer-encoding')?.includes('chunked'));
  const contentLength = parseInt(request.headers.get('content-length') ?? 0);
  // Absent content-length is as good as 0, as Transfer-Encoding: chunked is not allowed

  // Detect a pipe request to let it have any Content-Type and Length, including `Transfer-Encoding: chunked` header  
  const isPiped = new URL(request.url).pathname.startsWith('/pipe/');
  
  switch (true) {
    case isPiped:
      break; // Allowed to have any Content-Type and Length, including `Transfer-Encoding: chunked` header
    case contentLength === 0 && isNotChunked:
      break; // Doesn't matter what the content-type is as it wont be parsed
    case contentType.includes('application/json'):
    case contentType.includes('application/x-www-form-urlencoded'):
    case contentType.includes('text/plain'):
    case contentType.includes('text/html'):
      if (contentLength <= bodyLimit) break;
    default:
      let errMessage;
      if (contentLength > bodyLimit) {
        errMessage = `Content-Length ${contentLength} is not within ${bodyLimit}`;
      } else {
        errMessage = `Content-Type '${contentType}' is not allowed`;        
      }
      return Response.json(
        { message: errMessage, error: "Bad Request", statusCode: 400 },
        {
          status: 400,
          statusText: "Bad Request",
          headers: {"Access-Control-Allow-Origin":"*"}
        }
      )
  }
  
  // If one invocation of this middleware modifies the Request and resends,
  // another invocation of this middleware will intercept it before it reaches the backend.
  // The following flag tells the latter invocation that it need not re-process the request.
  const isFromMiddleware = request.headers.get('x-middleware') === middlewareSig;

  // Ratelimiting by ip is too restrictive: may block users accessing internet from the same router
  const ratelimitBy = [
    request.method,
    new URL(request.url).pathname,
    ipAddress(request)
  ].join('@');

  // For requests from middleware, no rate-limiting is necessary
  const { success, reset } = isFromMiddleware ? { success: true, reset: 0 } : await ratelimit.limit(ratelimitBy);

  if (success) {
    switch (true) {
      case isPiped:
        if (! isFromMiddleware) return processPipe(request);
      default:
        return next();
    }
  } else {
    return Response.json(
      { message: `Try after ${(reset - Date.now())/1000} seconds`, error: "Too Many Requests", statusCode: 429 },
      {
      status: 429,
      statusText: "Too Many Requests",
      headers: {"Access-Control-Allow-Origin":"*"}
      }
    )
  }
}
