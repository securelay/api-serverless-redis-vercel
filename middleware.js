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

export default async function middleware(request) {
  // You could alternatively limit based on user ID or similar
  const ip = ipAddress(request) || '127.0.0.1'
  const { success, pending, reset } = await ratelimit.limit(
    ip
  )

  await pending;

  return success ? next() : Response.json(
    { message: `Try after ${(reset - Date.now())/1000} seconds`, error: "Too Many Requests", statusCode: 429 },
    {
      status: 429,
      statusText: "Too Many Requests",
      headers: {"Access-Control-Allow-Origin":"*"}
    },
  )
}
