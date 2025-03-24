/*
Refs:
https://upstash.com/docs/redis/sdks/ts/pipelining/pipeline-transaction
https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
*/
import { fromUint8Array as base64encode } from 'js-base64';
import { Redis } from '@upstash/redis';
import { Octokit } from '@octokit/core';
import { createOrUpdateTextFile } from '@octokit/plugin-create-or-update-text-file';
import { waitUntil } from '@vercel/functions';

const kvCache = {};

const secret = process.env.SECRET;
const sigLen = parseInt(process.env.SIG_LEN);
const hashLen = parseInt(process.env.HASH_LEN);
const ttl = parseInt(process.env.TTL);
const cacheTtl = parseInt(process.env.CACHE_TTL);
const cdnTtl = parseInt(process.env.CDN_TTL)*86400; // convert days into seconds
const streamTimeout = parseInt(process.env.STREAM_TIMEOUT);
const maxStreamCount = parseInt(process.env.MAX_STREAM_COUNT);
const maxPublicPostCount = parseInt(process.env.MAX_PUBLIC_POSTS_RETAINED);
const maxFieldsCount = parseInt(process.env.MAX_PRIVATE_POST_FIELDS);
const pipingServerURL = process.env.PIPING_SERVER_URL;
const defunctPipePlumbTimeout = parseInt(process.env.DEFUNCT_PIPE_PLUMB_TIMEOUT);

const dbKeyPrefix = {
                manyToOne: "m2o:",
                oneToMany: "kv:",
                oneToOne: "o2o:",
                cache: "cache:",
                pipe: {
                  send: "pipeSend:",
                  receive: "pipeRecv:"
                },
                cdn: "cdn:"
            }

// Redis client for user database
const redisData = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL_MAIN,
  token: process.env.UPSTASH_REDIS_REST_TOKEN_MAIN,
  latencyLogging: false,
  enableAutoPipelining: true
})
// Redis client for ratelimiter database
const redisRateLimit = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL_CACHE,
  token: process.env.UPSTASH_REDIS_REST_TOKEN_CACHE,
  latencyLogging: false,
  enableAutoPipelining: true
})

// Setup Octokit for accessing the GitHub API
const MyOctokit = Octokit.plugin(createOrUpdateTextFile);
const octokit = new MyOctokit({ auth: process.env.GITHUB_PAT });

// Run specified script (provided as {hash, script}) with evalsha.
// If evalsha fails, loads script to redis and reruns evalsha.
async function safeEval(script, keys, args){
  try {
    return await redisData.evalsha(script.hash, keys, args);
  } catch(err) {
    if (err.message.includes('NOSCRIPT')) {
      const sha1 = await redisData.scriptLoad(script.script);
      if (sha1 !== script.hash) throw new Error(
        `Expected scipt hash ${script.hash}. Got ${sha1}.`
      );
      return redisData.evalsha(script.hash, keys, args); 
    }
    throw err;
  }
}

export async function hash(str){
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return crypto.subtle.digest('SHA-256', data)
      .then((buffer) => base64encode(new Uint8Array(buffer), true).substring(0,hashLen));
}

export async function sign(str){
    const encoder = new TextEncoder();
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), algorithm, false, ["sign", "verify"]);
    return crypto.subtle.sign(algorithm.name, key, encoder.encode(str))
      .then((buffer) => base64encode(new Uint8Array(buffer), true).substring(0,sigLen));
}

// Brief: Return random base64url string of given length
export function randStr(len = hashLen){
  const byteSize = Math.ceil(len*6/8); // base64 char is 6 bit, byte is 8
  const arr = new Uint8Array(byteSize);
  crypto.getRandomValues(arr);
  return base64encode(arr, true).substring(0,len);
}

export async function id(){
    return sign('id');
}

// Conversion table for key-type <=> Base64-digit (code)
// In future, there may be more key types other than private and public.
// E.g. public keys with read-only / write-only / read+write access.
const keyTypeCode = { A: 'private', B: 'public' };

// Returns keyTypeCode if arg is keyType, and vice-versa.
function keyType(arg){
  if (arg.length === 1) {
    // arg is a single letter code
    return keyTypeCode[arg];
  } else {
    // arg is a multi-letter(word) type
    return Object.entries(keyTypeCode).find(([code, type]) => type === arg)[0];
  }
}

// Parse given key into its distinct parts (Returns JSON object).
// If required part is provided, returns only that part.
// Also validates key by default, disable with option {validate: false}.
export async function parseKey(key, { validate = true, part } = {}){
  const parsed = {};
  parsed.type = keyType(key[0]);
  parsed.signature = key.substring(1, sigLen + 1);
  parsed.random = key.substring(sigLen + 1);
  if ( validate && parsed.signature !== await sign(parsed.random + parsed.type) ) {
    throw new Error('Invalid Key');
  }
  if (part) {
    return parsed[part];
  } else {
    return parsed;
  }
}

// Check if given public key is blacklisted
// If blacklisted, `PUBLICKEY.json` would exist in https://github.com/securelay/blacklist
export async function isBlacklisted(publicKey){
  const url = `https://raw.githubusercontent.com/securelay/blacklist/main/${publicKey}.json`;
  return fetch(url, {
    method: 'HEAD',
    signal: AbortSignal.timeout(1000) // Timeout request after 1000 ms
  }).then((response) => response.ok)
    .catch((err) => false); // Assume whitelisted if query times out or throws other errors
}

// Also validates key by default, disable with option {validate: false}.
export async function genPublicKey(privateOrPublicKey, { validate = true } = {}){
    const { type, random, signature } = await parseKey(privateOrPublicKey, { validate: validate });
    if (type === 'public') return privateOrPublicKey;
    // In future, there may be more key types other than private and public.
    // For valid keys, if any, that can't generate a public key, the following check is needed.
    if (type !== 'private') return undefined;
    const publicRandom = await hash(random); // Hash private-key's random to get public-key's random
    const publicKey = keyType('public') + await sign(publicRandom + 'public') + publicRandom;
    if (validate && await isBlacklisted(publicKey)) throw new Error('Blacklisted');
    return publicKey;
}

export async function genKeyPair(){
    const privateRandom = randStr(hashLen);
    const privateKey = keyType('private') + await sign(privateRandom + 'private') + privateRandom;
    const publicKey = await genPublicKey(privateKey, { validate: false });
    return {private: privateKey, public: publicKey};
}

export async function cacheSet(privateOrPublicKey, obj){
    const publicKey = await genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + await parseKey(publicKey, { validate: false, part: "random" });
    // Promise.all below enables both commands to be executed in a single http request (using same pipeline)
    // As Redis is single-threaded, the commands are executed in order
    // See https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
    return Promise.all([
      redisRateLimit.hset(dbKey, obj),
      redisRateLimit.expire(dbKey, cacheTtl)
    ])
}

// Demand for data also refreshes its expiry
// If multiple keys are provided comma-separated as key1, key2, ..., returns json obj: {key1: val1, key2: val2, ...}
// If only a single key is provided, returns the corresponding value as string
export async function cacheGet(privateOrPublicKey, ...keys){
    const publicKey = await genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + await parseKey(publicKey, { validate: false, part: "random" });
    const valuesObj = await Promise.all([
      redisRateLimit.hmget(dbKey, ...keys),
      redisRateLimit.expire(dbKey, cacheTtl)
    ]).then(([obj,]) => obj ?? {}) // hmget() returns null if none of the keys is in the redis hash
    if (keys.length === 1) return valuesObj[keys[0]]; // If `keys` has a single key only, return only its value
    return valuesObj;
}

export async function cacheDel(privateOrPublicKey, key){
    const publicKey = await genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + await parseKey(publicKey, { validate: false, part: "random" });
    return redisRateLimit.hdel(dbKey, key);
}

// Add metadata to payload (which must be a JSON object)
// Some metadata are auto-generated:
//  id: string to uniquely identify a payload
//  time: Unix-time in seconds
// Other metadata may be provided as the optional `fields` JSON object
// Properties in `fields` override the autogenerated properties
export function decoratePayload(payload, fields={}){
  if (Object.keys(payload).length === 0) throw new Error('No Payload');
  const generatedMeta = {id: randStr(), time: Math.round(Date.now()/1000)};
  return {...generatedMeta, ...fields, data: payload};
}

export async function publicProduce(publicKey, data){
    const dbKey = dbKeyPrefix.manyToOne + await parseKey(publicKey, { part: "random" });
    const [ count, ] = await Promise.all([
      redisData.rpush(dbKey, data),
      redisData.expire(dbKey, ttl)
    ])
    if (count > maxPublicPostCount) return redisData.ltrim(dbKey, count - maxPublicPostCount, -1);
}

export async function privateConsume(privateKey){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.manyToOne + await parseKey(publicKey, { validate: false, part: "random" });
    return redisData.lpop(dbKey, maxPublicPostCount);
}

// Sets Key-Val pair(s) for the KV mode
// Keys are stored in a Redis hash as is with prefix 'key:'
// Corresponding views are stored as hash(key) with prefix 'views:'
// Password, if provided, is stored against key: 'passwd:'
// N views means after N more views the corresponding key-val will be deleted
export async function kvSet(privateKey, kvObj, { password, views, fresh=false }={} ){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { validate: false, part: "random" });

    // Number coercion. Could also use unary + to turns empty strings into 0
    const viewsCount = Number(views);

    // Prepare hash to be stored in Redis
    const redisHash = {};
    for (const key in kvObj) {
        redisHash['key:'+key] = kvObj[key];
        if (!Number.isNaN(viewsCount)) redisHash['views:'+await hash(key)] = -viewsCount;
    }

    if (password) redisHash['passwd:'] = await hash(password);

    let existingKeys;
    if (fresh) {
      redisData.del(dbKey);
      existingKeys = [];
    } else {
      existingKeys = await redisData.hkeys(dbKey);
    }
    const stagedKeys = Object.keys(redisHash);
    if (new Set(existingKeys.concat(stagedKeys)).size > maxFieldsCount) throw new Error('Insufficient Storage');

    return Promise.all([
      redisData.hset(dbKey, redisHash),
      redisData.expire(dbKey, ttl)
    ]);
}

// Caches all or selected key-vals in `kvCache` for use by others.
// So, pulling the key-vals from the DB can be done once only.
// Accessing data refreshes expiry.
// Note: Optionally, provide redis-hash-keys instead of user's keys from kv
async function cacheKV(dbKey, ...redisHashKeys){
  if (Object.keys(kvCache).length) return; // Dont proceed if already cached
  redisData.expire(dbKey, ttl); // Puts command in auto-pipeline
  if (redisHashKeys.length) {
    // Pull provided keys only, to save bandwidth
    Object.assign(kvCache, await redisData.hmget(dbKey, ...redisHashKeys));
  } else {
    // Pull all keys
    Object.assign(kvCache, await redisData.hgetall(dbKey));
  }
}

// Gets all key-vals in kv mode.
export async function kvScan(privateKey){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { validate: false, part: "random" });
    await cacheKV(dbKey);
    return Object.keys(kvCache)
      .filter((redisHashKey) => redisHashKey.startsWith('key:'))
      .reduce((obj, redisHashKey) => {
          const key = redisHashKey.substring(4); // Substring to remove the prefix 'key:'
          obj[key] = kvCache[redisHashKey];
          return obj;
        },
        {}
      )
}

// Gets all key-views in kv mode.
export async function kvViews(privateKey){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { validate: false, part: "random" });
    await cacheKV(dbKey);
    const kvViewsObj = {};
    for (const redisHashKey in kvCache) {
      if (!redisHashKey.startsWith('key:')) continue;
      const key = redisHashKey.substring(4); // Substring to remove the prefix 'key:'
      kvViewsObj[key] = kvCache['views:' + await hash(key)];
    }
    return kvViewsObj;
}

export async function kvDelete(privateKey, ...keys){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { validate: false, part: "random" });
    if (keys.length) {
      const redisHashKeys = [];
      for (const key of keys) redisHashKeys.push('key:' + key, 'views:' + await hash(key));
      return redisData.hdel(dbKey, ...redisHashKeys);
    } else {
      return redisData.del(dbKey);
    }
}

export async function kvRefresh(privateKey){
    const publicKey = await genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { validate: false, part: "random" });
    return redisData.expire(dbKey, ttl);
}

export async function privateStats(privateKey){
    const publicKey = await genPublicKey(privateKey);
    const publicKeyRandom = await parseKey(publicKey, { validate: false, part: "random" })
    const dbKeyConsume = dbKeyPrefix.manyToOne + publicKeyRandom;
    const dbKeyPublish = dbKeyPrefix.oneToMany + publicKeyRandom;
    const [ countConsume, ttlConsume ] = await Promise.all([
      redisData.llen(dbKeyConsume),
      redisData.ttl(dbKeyConsume)
    ])
    return {
        count: countConsume,
        ttl: ttlConsume < 0 ? 0 : ttlConsume
    };
}

// Demand for data also refreshes its expiry
export async function kvGet(publicKey, password, ...kvKeys){
    const dbKey = dbKeyPrefix.oneToMany + await parseKey(publicKey, { part: "random" });

    const redisHashKeys = ['passwd:',];
    const viewsKeyMap = {};
    for (const key of kvKeys) {
      redisHashKeys.push('key:'+key);
      viewsKeyMap[key] = 'views:'+await hash(key);
    }
    redisHashKeys.push(...Object.values(viewsKeyMap));

    await cacheKV(dbKey, ...redisHashKeys);

    const kvObj = {};
    const delHashKeys = [];
    const incrHashCtrs = {};

    if (kvCache['passwd:'] == null || kvCache['passwd:'] === await hash(password)) {
      kvKeys.forEach((key) => {
        const val = kvCache['key:'+key];
        if (val == null) return;
        kvObj[key] = val;
        const count = kvCache[viewsKeyMap[key]];
        if (count == -1) {
          delHashKeys.push('key:'+key, viewsKeyMap[key]);
        } else {
          incrHashCtrs[viewsKeyMap[key]] = count+1;
        }
      })
      if (Object.keys(incrHashCtrs).length) waitUntil(redisData.hset(dbKey, incrHashCtrs));
      if (delHashKeys.length) waitUntil(redisData.hdel(dbKey, ...delHashKeys));
    } else {
      throw new Error('Unauthorized');
    }
    
    if (kvKeys.length > 1) {
      return kvObj;
    } else {
      return kvObj[kvKeys[0]];
    }
}

export async function oneToOneProduce(privateKey, channel, data, { evict=false, overwrite=false }={}){
    const publicKey = await genPublicKey(privateKey);
    const dbKeySortedSet = dbKeyPrefix.oneToOne + await parseKey(publicKey, { validate: false, part: "random" });
    const member = await hash([publicKey, channel].join('/'));
    const dbKeyChannel = dbKeyPrefix.oneToOne + member;
    const timeNow = Math.round(Date.now()/1000); // Unix-time in seconds
    
    const [ added, novel, currFieldCount ] = await Promise.all([
      // Returns truthy if added
      redisData.set(dbKeyChannel, data, { nx: !overwrite, ex: ttl }),
      // Returns number of new members, not including those whose scores merely got reset
      redisData.zadd(dbKeySortedSet, { nx: !overwrite }, { score: timeNow, member }),
      redisData.zcard(dbKeySortedSet)
    ]);

    // The following won't be needed had we used eval or atomicTransaction. But those increase the command count.
    // If interleaved with non-atomic oneToOneConsume() for the same channel, the following condition might be truthy
    // Imagine set succeeded by oneToOneConsume() succeeded by zadd
    // The next set would succeed even if overwrite is not specified
    // But the subsequent zadd would fail due to nx conflict, if overwrite is not specified
    // So force zadd to succeed whenever set succeeds, even if overwrite is not specified
    if (added && !(novel || overwrite)) {
      await redisData.zadd(dbKeySortedSet, { nx: false }, { score: timeNow, member });
    }

    // If storage is full and novelty has been added
    if (novel && currFieldCount > maxFieldsCount) {
      const countAfterStaleRemoval = currFieldCount - await redisData.zremrangebyscore(
        dbKeySortedSet, 0, timeNow - ttl
      );
      if (countAfterStaleRemoval <= maxFieldsCount) return;
      if (evict) {
        // Delete oldest (LRU) channel
        const toBeEvictedKeys = await redisData.zpopmin(dbKeySortedSet, countAfterStaleRemoval - maxFieldsCount)
          .then((arr) => arr.filter((_,i) => i%2 == 0).map((el) => dbKeyPrefix.oneToOne + el));
        waitUntil(redisData.del(...toBeEvictedKeys));
      } else {
        // Delete last added channel
        waitUntil(oneToOneConsume(publicKey, channel));
        throw new Error('Insufficient Storage');
      }
      return;
    }
    
    if(!(added || overwrite)) throw new Error('Already Exists');
}

export async function oneToOneConsume(publicKey, channel){
    const dbKeySortedSet = dbKeyPrefix.oneToOne + await parseKey(publicKey, { part: "random" });
    const member = await hash([publicKey, channel].join('/'));
    const dbKeyChannel = dbKeyPrefix.oneToOne + member;
    
    // redis lua script
    const script = {
      script: `
        local value = redis.call('GETDEL', KEYS[1])
        redis.call('ZREM', KEYS[2], ARGV[1])
        return value
      `,
      hash: '6c7f115a4becb9fb6230fee33782bc9439b9a6f7'
    }
    
    return safeEval(script, [dbKeyChannel, dbKeySortedSet], [member]);
}

export async function oneToOneTTL(privateKey, channel){
    const publicKey = await genPublicKey(privateKey);
    const dbKeyChannel = dbKeyPrefix.oneToOne + await hash([publicKey, channel].join('/'));
    const _ttl = await redisData.ttl(dbKeyChannel);
    return (_ttl < 0) ? 0 : _ttl;
}

// Whether provided http method means 'send' or 'receive' mode.
// If option `complement` is true, returns the complementary mode instead.
function methodToMode(method, complement=false){
  const table = { send: ['POST', 'PUT'], receive: ['GET', 'HEAD'] };
  const mode = Object.keys(table).find((key) => {
    return table[key].includes(method) === !complement;
  })
  if (!mode) throw new Error('Method Not Allowed');
  return mode;
}

// Plumbs defunct private pipes with bodyless http-requests under timeout
function plumbDefunctPipes(tokens, privateMode){
  // If private mode is sending, plumb with 'GET'.
  // Plumb with 'POST', otherwise.
  const table = {send: 'GET', receive: 'POST'};
  if (Boolean(tokens?.length) === false) return;
  const method = table[privateMode];
  const opts = {
    method,
    body: '',
    signal: AbortSignal.timeout(defunctPipePlumbTimeout)
  }
  tokens.forEach((el) => {
    const [ token, ] = el.split('@');
    waitUntil(fetch(pipingServerURL + token, opts).catch((err) => {}));
  })
}

// streamTimeout simply guarantees that a pipe, if plumbed, will be plumbed within that time period.
// Tokens are stored in LIFO stacks of finite max length.
// New tokens evict old ones, once stack is filled.
// Pipes corresponding to evicted tokens are never discovered, i.e. are defunct.
// Defunct pipes are plumbed later with bodyless pipes: see plumbDefunctPipes().
// Timestamps (Unix-time in seconds) are stored with the tokens using string concatenation.
export async function pipeToPublic(privateKey, httpMethod){
  const publicKey = await genPublicKey(privateKey);
  const privateMode = methodToMode(httpMethod);
  const dbKey = dbKeyPrefix.pipe[privateMode] + await parseKey(publicKey, { validate: false, part: "random" });
  const token = randStr();
  const timeNow = Math.round(Date.now()/1000);
  const [ count, ] = await Promise.all([
    redisData.lpush(dbKey, token + '@' + timeNow),
    redisData.expire(dbKey, streamTimeout)
  ])
  if (count > maxStreamCount) {
    const expiredTokens = await redisData.rpop(dbKey, count - maxStreamCount);
    plumbDefunctPipes(expiredTokens, privateMode);
  }
  return pipingServerURL + token;
}

// Expired, unused tokens imply defunct pipes (see above).
export async function pipeToPrivate(publicKey, httpMethod){
  const privateMode = methodToMode(httpMethod, true);
  const dbKey = dbKeyPrefix.pipe[privateMode] + await parseKey(publicKey, { part: "random" });
  const fromDB = await redisData.lpop(dbKey);
  const timeNow = Math.round(Date.now()/1000);
  if (fromDB) {
    const [token, timestamp] = fromDB.split('@');
    // Expired unused tokens are possible as adding new tokens refreshes the expiry of the entire list
    // Return token if it is not expired
    // Because of LIFO, if the first-out token is expired, the entire list is expired, so pop those off
    if ((timeNow - timestamp) < streamTimeout) {
      return pipingServerURL + token;
    } else {
      const expiredTokens = await redisData.lpop(dbKey, maxStreamCount);
      plumbDefunctPipes([token+'@'+timestamp,...expiredTokens], privateMode);
    }
  }
}

export function OneSignalID(app){
  return process.env[`ONESIGNAL_APP_ID_${app.toUpperCase()}`];
}

export function OneSignalKey(app){
  return process.env[`ONESIGNAL_API_KEY_${app.toUpperCase()}`];
}

// Web-push data using OneSignal and registered app details.
// Parameter `data` must be valid JSON object, but not an array!
export async function OneSignalSendPush(app, origin, externalID, data=null){
  const OneSignalAPIKey = OneSignalKey(app);
  const OneSignalAppID = OneSignalID(app);
  const appObj = await fetch(`https://securelay.github.io/apps/${app.toLowerCase()}.json`)
    .then((response) => response.json())
    .catch((err) => undefined);
  if (! (OneSignalAPIKey && OneSignalAppID && appObj)) throw new Error('App is not recognized');

  // Return silently in case of origin mismatch
  const registeredOrigins = appObj.webPush.ifOrigin;
  if (registeredOrigins && registeredOrigins.includes(origin) == false) return;

  if (!appObj.webPush.sendData) delete data.data; // Delete private data from payload for security

  return fetch('https://api.onesignal.com/notifications?c=push', {
    method: 'POST',
    headers: {
      Authorization: `Key ${OneSignalAPIKey}`,
      'Content-type': 'application/json'
    },
    body: JSON.stringify({
      app_id: OneSignalAppID,
      include_aliases: {external_id: [externalID]},
      target_channel: 'push',
      contents: {en: appObj.webPush.message},
      isAnyWeb: true,
      web_push_topic: 'public post',
      mutable_content: true,
      enable_frequency_cap: false,
      data: data
    })  
  }).then((res) => res.json())
}

// Derive CDN URL from public key
export async function cdnURL(publicKey){
  const base = 'https://cdn.jsdelivr.net/gh';
  return `${base}/${process.env.GITHUB_OWNER_REPO}@main/` + await id() + `/${publicKey}.json`;
  // Alternately, if published as GitHub pages: `https://securelay.github.io/jsonbin/${endpointID}`;
  // Alternately: `https://raw.githubusercontent.com/securelay/jsonbin/main/${endpointID}`;
}

export async function queueForGitHubStore(privateKey, json=null, remove=false){
  const publicKey = await genPublicKey(privateKey);
  const jsonURL = await cdnURL(publicKey);

  let action;
  if (json && remove) {
    action = 'add';
  } else if (json && !remove) {
    const exists = await fetch(jsonURL, {
      method: 'HEAD',
      signal: AbortSignal.timeout(1000)
    })
    .then((res) => res.ok)
    .catch((err) => false);
    if (exists) {
      return;
    } else {
      action = 'add';
    }
  } else if (remove) {
    action = 'delete';
  } else {
    action = 'renew';
  }

  const dbKey = dbKeyPrefix.cdn;
  const cdnData = {publicKey, action, json, ttl: cdnTtl};
  const count = await redisData.rpush(dbKey, cdnData);
  if (count === 1) {
    const [ owner, repo ] = process.env.GITHUB_OWNER_REPO.split('/');
    await octokit.request('PUT /repos/{owner}/{repo}/issues/{issue_number}/labels', {
      owner,
      repo,
      issue_number: 1,
      labels: ['pull'],
      headers: {
        'X-GitHub-Api-Version': '2022-11-28'
      }
    })
  }
  return jsonURL;
}

// Push JSON (object) to be stored at https://securelay.github.io/jsonbin/{id}/{publicKey}.json
// The function adds metadata using decoratePayload() above.
// Do not pass JSON in order to touch existing data (i.e. update its timestamp).
// Pass null as `json` and true as `remove` for removing the stored data.
// Returns link to the data, if data is updated or deleted, false otherwise.
// Ref: https://github.com/octokit/plugin-create-or-update-text-file.js/
export async function githubPushJSON(privateKey, json=null, remove=false){
  const publicKey = await genPublicKey(privateKey);
  const jsonURL = await cdnURL(publicKey);
  const path = await id() + '/' + publicKey + '.json';
  const touch = Boolean(!(json || remove));
  const timeNow = Math.round(Date.now()/1000); // Unix-time in seconds
  let content, mode;
  
  if (touch) {
    // Do not commit to GitHub if re-touching within a day. Because CDN_TTL >> 1 day.
    // Avoiding GitHub traffic reduces blocking time, thus helping performance.
    const lastTouched = await cacheGet(publicKey, 'cdnRenewed');
    if (lastTouched && ((timeNow - lastTouched) < 86400)) return jsonURL;
    // Just update timestamp in metadata when `touch` is true;
    mode = 'touched';
    
    // Do nothing if file doesn't exist
    // Else, delete file if expired
    // Otherwise, just update the timestamp in the file
    content = ({exists, content}) => {
      if (!exists) return null;
      const json = JSON.parse(content);
      if ((timeNow - json.time) > cdnTtl) return null;
      json.time = timeNow;
      return JSON.stringify(json);
    }
  } else if (json === null) {
    mode = 'deleted';
    content = null;
  } else {
    mode = 'updated';
    content = JSON.stringify(decoratePayload(json));
  }
  
  const [ owner, repo ] = process.env.GITHUB_OWNER_REPO.split('/');
  const { updated, deleted } = await octokit.createOrUpdateTextFile({
    owner,
    repo,
    path,
    content,
    message: mode + ' ' + path,
  });

  if (mode === 'deleted') {
    await cacheDel(privateKey, 'cdnRenewed');
    if (deleted) return jsonURL;
  } else {
    await cacheSet(privateKey, { cdnRenewed: timeNow });
    // updated and deleted both being truthy means expiry
    if (updated && !deleted) return jsonURL;
  }
  return false; // Reaching this step means everything failed above
}
