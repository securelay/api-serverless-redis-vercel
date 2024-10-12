# About
This is a serverless, NodeJS implementation of the [Securelay API](https://github.com/securelay/specs).
It uses [Redis](https://redis.io/docs/latest/commands/) as database.
This particular implementation is configured to be hosted on [Vercel](https://vercel.com/pricing)
out of the box. However, with a few [variations](https://fastify.dev/docs/latest/Guides/Serverless/),
this implmentation may be run on any serverless platform such as [AWS Lambda](https://fastify.dev/docs/latest/Guides/Serverless/#aws),
provided a Redis DB, such as [Upstash](https://upstash.com/pricing/redis), can be used.

# How to host on Vercel

### Using GUI
- [Create](https://vercel.com/signup) a Vercel account.
- Get Redis in the form of [Vercel's KV store](https://vercel.com/docs/storage/vercel-kv/quickstart) and/or [Upstash](https://upstash.com/pricing/redis).
- Import [this](https://github.com/securelay/api-serverless-redis-vercel) project and deploy it by following [this tutorial](https://vercel.com/docs/getting-started-with-vercel/import).
- Note: Before deploying, set the environment variables through Vercel's Project Settings page by following the template provided in [example.env](./example.env).

### Using CLI
- [Create](https://vercel.com/signup) a Vercel account.
- Get Redis in the form of [Vercel's KV store](https://vercel.com/docs/storage/vercel-kv/quickstart) and/or [Upstash](https://upstash.com/pricing/redis).
- Set the environment variables through Vercel's Project Settings page by following the template provided in [example.env](./example.env).
- Get vercel CLI: `npm i -g vercel`.
- Clone this repo: `git clone https://github.com/securelay/api-serverless-redis-vercel`.
- `cd api-serverless-redis-vercel`.
- `vercel login`.
- Deploy locally and test: `vercel dev`.
- If everything is working fine deploy publicly on Vercel: `vercel`.

# Note on Redis
This implementation, given its serverless nature, uses the REST API provided by [Upstash](https://upstash.com/docs/redis/features/restapi) for accessing Redis.

One database, provided directly by [Upstash](https://upstash.com/pricing/redis), is used for storing user data.
Another database, provided by [Vercel's KV store](https://vercel.com/docs/storage/vercel-kv/quickstart), is used by the rate-limiter.
If you can manage a large enough Redis database, you can use it for both the above purposes, instead of using two different databases.
The `dbKeyPrefix`, used in [helper.js](api/helper.js), would prevent key collisions.
