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

const cache = new Map(); // must be outside of your serverless function handler

const ratelimit = new Ratelimit({
  redis: new Redis({
    url: process.env.KV_REST_API_URL,
    token: process.env.KV_REST_API_TOKEN,
  }),
  ephemeralCache: cache,
  analytics: false,
  limiter: Ratelimit.slidingWindow(parseInt(process.env.RATELIMIT), process.env.RATELIMIT_WINDOW + ' s'),
  prefix: "rl:",
  enableProtection: true
})

// Forwards requests at path /pipe/* to /stream/* in index.js after trimming the request body and headers
// and returns the response. This is done in middleware.js because, unlike index.js, middleware.js doesn't have
// problems with the `Expect: 100-continue` header sent by `curl -T- <url>`. middleware.js also doesn't read the
// request body. index.js also has a set bodyLimit which is incompatible with payloads at /pipe/* of arbitrary size.
// /stream/ path is exposed only to middleware.
// For requests not at path /pipe/*, returns null.
async function pipeToStream(request) {
  const pipeUrl = new URL(request.url);
  if (!pipeUrl.pathname.startsWith('/pipe/')) return null;
  const streamUrl = pipeUrl.href.replace('/pipe/', '/stream/');
  return fetch(streamUrl, { method: request.method, headers: { 'x-middleware' : middlewareSig }, redirect: 'manual' });
}

export default async function middleware(request) {
  const fromMiddleware = request.headers.get('x-middleware') === middlewareSig;

  // You could alternatively rate-limit based on user ID or similar
  const ip = ipAddress(request) || '127.0.0.1';
  // For requests from middleware, no rate-limiting is necessary
  const { success, reset } = fromMiddleware ? { success: true, reset: 0 } : await ratelimit.limit(ip);

  if (success) {
    const streamResponse = await pipeToStream(request);
    // For non-pipe requests, streamResponse is null.
    return streamResponse ?? next();
  }
  else {
    return Response.json(
    { message: `Try after ${(reset - Date.now())/1000} seconds`, error: "Too Many Requests", statusCode: 429 },
    {
      status: 429,
      statusText: "Too Many Requests",
      headers: {"Access-Control-Allow-Origin":"*"}
    },
  )
  }
}
