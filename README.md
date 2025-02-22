# About
This is a serverless, NodeJS implementation of the [Securelay API](https://github.com/securelay/specs), using [Upstash/Redis](https://upstash.com/docs/redis/help/faq) as database.
It is configured to be hosted on [Vercel](https://vercel.com/pricing)'s Fluid Compute
out of the box. However, with a few [variations](https://fastify.dev/docs/latest/Guides/Serverless/),
this implementation may be run on any serverless platform such as [Cloudflare Workers](https://developers.cloudflare.com/workers/platform/pricing/), [Netlify functions](https://www.netlify.com/pricing/) or [AWS Lambda](https://aws.amazon.com/lambda/pricing/). If [Upstash/Redis](https://upstash.com/pricing/redis) becomes unavailable, any of its drop-in replacements, such as [Momento](https://www.gomomento.com/pricing/), may be used.

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

# FAQ

### Why serverless?
Because of
- cheaper compute / generous free-tiers
- managed infra
    - elastic scaling
    - DDoS mitigation
    - static asset CDN
- ease of deployment
- ease of development

### Why Vercel?
Because it is good for prototyping and getting hang of the serverless world. Adaptations for Cloudflare Workers and Netlify are planned.

### Why Redis?
Because Redis's `string`, `list` and `hash` datatypes fit Securelay's data model perfectly. Script `eval` can efficiently execute most CRUD operations offered by Securelay. `expire` and `hexpire` takes care of Securelay's ephemeral nature easily.

### Why Upstash?
Because their web-API to Redis is tailor-made for serverless, where ephemeral function instances cannot maintain persistent connections to the DB. Also Upstash provides excellent open-source SDKs.

### Why only a single function?
Some serverless providers may not support multiple functions. Also, only a single function means less cold-starts.

### Why Fastify?
Just to make life easy during prototyping, as regards request parsing, request body limiting, routing etc. Future versions must get rid of the dependency to reduce deployment size and save on the GB-Hrs.

### Which JS APIs/Modules/Runtime?
Vercel's functions run on NodeJS runtime, whereas the middleware run on Edge runtime, which is a lightweight runtime based on V8. Cloudflare Workers run on V8. So, while choosing APIs/Modules, one needs to go for as much portability between runtimes as possible. Case in point 'node:crypto' and 'Web-Crypto'.
