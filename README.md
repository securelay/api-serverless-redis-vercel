# About
This is a serverless, NodeJS implementation of the [Securelay API](https://github.com/securelay/specs), using [Redis](https://redis.io/docs/latest/commands/) as database.
It is configured to be hosted on [Vercel](https://vercel.com/pricing)'s Fluid Compute
out of the box. However, with a few [variations](https://fastify.dev/docs/latest/Guides/Serverless/),
this implmentation may be run on any serverless platform such as [AWS Lambda](https://fastify.dev/docs/latest/Guides/Serverless/#aws),
provided a Redis DB with REST API, such as offered by [Upstash](https://upstash.com/pricing/redis), can be used.

# How to host on Vercel

### Using GUI
- [Create](https://vercel.com/signup) a Vercel account.
- Get Redis REST API in the form of [Upstash](https://upstash.com/pricing/redis).
- Import [this](https://github.com/securelay/api-serverless-redis-vercel) project and deploy it by following [this tutorial](https://vercel.com/docs/getting-started-with-vercel/import).
- Note: Before deploying, set the environment variables through Vercel's Project Settings page by following the template provided in [example.env](./example.env).
- Note: Before deploying, enable [Fluid Compute](https://vercel.com/docs/functions/fluid-compute).

### Using CLI
- [Create](https://vercel.com/signup) a Vercel account.
- Get Redis REST API in the form of [Upstash](https://upstash.com/pricing/redis).
- Set the environment variables through Vercel's Project Settings page by following the template provided in [example.env](./example.env).
- Enable [Fluid Compute](https://vercel.com/docs/functions/fluid-compute).
- Get vercel CLI: `npm i -g vercel`.
- Clone this repo: `git clone https://github.com/securelay/api-serverless-redis-vercel`.
- `cd api-serverless-redis-vercel`.
- `vercel login`.
- Deploy locally and test: `vercel dev`.
- If everything is working fine, deploy to production on Vercel: `vercel --prod`.

# Note on Redis
This implementation, given its serverless nature, uses the REST API provided by [Upstash](https://upstash.com/docs/redis/features/restapi) for accessing Redis.

One database (i.e. user-account in [Upstash](https://upstash.com/pricing/redis)), is used as the main silo, whereas another is used as cache, and also for rate-limiting.
If you can manage a large enough Redis database, you can use it for both the above purposes, simply by providing its credentials for both main and cache in the [environment variables](/example.env).
If using a single database, the `dbKeyPrefix` used in [helper.js](api/helper.js) prevents key collisions.

### Sharding
If using free-tiers of Upstash, multiple accounts may be used to scale up the main silo. User data may then be distributed among the shards based on, say, the first letter of [`<random>` of the Securelay public key](https://github.com/securelay/specs#implementation-details). E.g. if number of shards = 5, and the key is 'D', the shard index would be $`D_{base64url}\ \% \ 5`$.

# Note on CDN
This implementation uses a GitHub repo for storing CDN data. [jsDelivr](https://www.jsdelivr.com/) is then used to serve the content through its CDN.

To this aim, create a GitHub repo and a fine-grained access token [`GITHUB_PAT`](/example.env) with write access.

# Contact
If you have any queries, comments or feedback, please [get in touch](https://github.com/securelay/securelay.github.io/discussions/1).
