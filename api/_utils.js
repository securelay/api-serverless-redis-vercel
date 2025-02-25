/*
Refs:
https://upstash.com/docs/redis/sdks/ts/pipelining/pipeline-transaction
https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
*/
import { hash as cryptoHash, createHmac, getRandomValues } from 'node:crypto';
import { Buffer } from "node:buffer";
import { Redis } from '@upstash/redis';
import { Octokit } from '@octokit/core';
import { createOrUpdateTextFile } from '@octokit/plugin-create-or-update-text-file';
import { waitUntil } from '@vercel/functions';

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
                oneToMany: "o2m:",
                oneToOne: "o2o:",
                cache: "cache:",
                pipe: {
                  send: "pipePubSend:",
                  receive: "pipePubRecv:"
                }
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

function hash(str){
    return cryptoHash('md5', str, 'base64url').substring(0,hashLen);
    // For small size str crypto.hash() is faster than crypto.createHash()
    // Ref: https://nodejs.org/api/crypto.html#cryptohashalgorithm-data-outputencoding
}

function sign(str){
    // Ref: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
    return createHmac('md5', secret).update(str).digest('base64url').substring(0,sigLen);
}

// Brief: Return random base64url string of given length
function randStr(len = hashLen){
  const byteSize = Math.ceil(len*6/8); // base64 char is 6 bit, byte is 8
  const buff = Buffer.alloc(byteSize);
  getRandomValues(buff);
  return buff.toString('base64url').substring(0,len);
}

export function id(){
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
export function parseKey(key, { validate = true } = {}){
  const parsed = {};
  parsed.type = keyType(key[0]);
  parsed.signature = key.substring(1, sigLen + 1);
  parsed.random = key.substring(sigLen + 1);
  if ( validate && parsed.signature !== sign(parsed.random + parsed.type) ) {
    throw new Error('Invalid Key');
  }
  return parsed;
}

// Also validates key by default, disable with option {validate: false}.
export function genPublicKey(privateOrPublicKey, { validate = true } = {}){
    const { type, random, signature } = parseKey(privateOrPublicKey, { validate: validate });
    if (type === 'public') return privateOrPublicKey;
    // In future, there may be more key types other than private and public.
    // For valid keys, if any, that can't generate a public key, the following check is needed.
    if (type !== 'private') return undefined;
    const publicRandom = hash(random); // Hash private-key's random to get public-key's random
    return keyType('public') + sign(publicRandom + 'public') + publicRandom;
}

export function genKeyPair(){
    const privateRandom = randStr(hashLen);
    const privateKey = keyType('private') + sign(privateRandom + 'private') + privateRandom;
    const publicKey = genPublicKey(privateKey, { validate: false });
    return {private: privateKey, public: publicKey};
}

export async function cacheSet(privateOrPublicKey, obj){
    const publicKey = genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + parseKey(publicKey, { validate: false }).random;
    // Promise.all below enables both commands to be executed in a single http request (using same pipeline)
    // As Redis is single-threaded, the commands are executed in order
    // See https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
    return Promise.all([
      redisRateLimit.hset(dbKey, obj),
      redisRateLimit.expire(dbKey, cacheTtl)
    ])
}

// Demand for data also refreshes its expiry
export async function cacheGet(privateOrPublicKey, key){
    const publicKey = genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + parseKey(publicKey, { validate: false }).random;
    return Promise.all([
      redisRateLimit.hget(dbKey, key),
      redisRateLimit.expire(dbKey, cacheTtl)
    ]).then((values) => values[0]);
}

export async function cacheDel(privateOrPublicKey, key){
    const publicKey = genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + parseKey(publicKey, { validate: false }).random;
    return redisRateLimit.hdel(dbKey, key);
}

// Add metadata to payload (which must be a JSON object)
// Some metadata are auto-generated:
//  id: string to uniquely identify a payload
//  time: Unix-time in seconds
// Other metadata may be provided as the optional `fields` JSON object
// Properties in `fields` override the autogenerated properties
// `passwd`, if provided, is hashed and stored as metadata property `__lock__`.
export function decoratePayload(payload, fields={}, passwd=null){
  if (Object.keys(payload).length === 0) throw new Error('No Payload');
  const generatedMeta = {id: randStr(), time: Math.round(Date.now()/1000)};
  const lockMeta = {};
  // Check if passwd is not null or undefined.
  // Note: check passes even if passwd is empty string as '' can be hashed.
  if (passwd != null) lockMeta['__lock__'] = hash(passwd);
  return {...generatedMeta, ...fields, ...lockMeta, data: payload};
}

// Removes `__lock__` property from json object after matching its value against provided `passwd`.
export function unlockJSON(json, passwd){
  if (! '__lock__' in json) return json;
  if (json['__lock__'] === hash(passwd)) {
    delete(json['__lock__']);
    return json;
  }
}

export async function publicProduce(publicKey, data){
    const dbKey = dbKeyPrefix.manyToOne + parseKey(publicKey).random;
    const [ count, ] = await Promise.all([
      redisData.rpush(dbKey, data),
      redisData.expire(dbKey, ttl)
    ])
    if (count > maxPublicPostCount) return redisData.ltrim(dbKey, count - maxPublicPostCount, -1);
}

export async function privateConsume(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.manyToOne + parseKey(publicKey, { validate: false }).random;
    const atomicTransaction = redisData.multi();
    atomicTransaction.lrange(dbKey, 0, -1);
    atomicTransaction.del(dbKey);
    return atomicTransaction.exec()
      .then((values) => values[0]);
}

export async function privateProduce(privateKey, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + parseKey(publicKey, { validate: false }).random;
    return redisData.set(dbKey, data, { ex: ttl });
}

export async function privateDelete(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + parseKey(publicKey, { validate: false }).random;
    return redisData.del(dbKey);
}

export async function privateRefresh(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + parseKey(publicKey, { validate: false }).random;
    return redisData.expire(dbKey, ttl);
}

export async function privateStats(privateKey){
    const publicKey = genPublicKey(privateKey);
    const publicKeyRandom = parseKey(publicKey, { validate: false }).random
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
export async function publicConsume(publicKey){
    const dbKey = dbKeyPrefix.oneToMany + parseKey(publicKey).random;
    return redisData.getex(dbKey, { ex: ttl });
}

export async function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + parseKey(publicKey, { validate: false }).random;
    const field = hash(key);
    const [ fieldExists, currFieldCount ] = await Promise.all([
      redisData.hexists(dbKey, field),
      redisData.hlen(dbKey)
    ])
    if ((!fieldExists) && (currFieldCount >= maxFieldsCount)) throw new Error('Insufficient Storage');
    // Ideally there should be hexpire() in Upstash's Redis SDK.
    // Until it's available, we expire the containing key as follows.
    return Promise.all([
      redisData.hset(dbKey, {[field]: data}),
      redisData.expire(dbKey, ttl)
    ])
}

export async function oneToOneConsume(publicKey, key){
    const dbKey = dbKeyPrefix.oneToOne + parseKey(publicKey).random;
    const field = hash(key);
    const atomicTransaction = redisData.multi();
    atomicTransaction.hget(dbKey, field);
    atomicTransaction.hdel(dbKey, field);
    return atomicTransaction.exec()
      .then((values) => values[0]);
}

export async function oneToOneTTL(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + parseKey(publicKey, { validate: false }).random;
    const field = hash(key);
    // Ideally there should be httl() in Upstash's Redis SDK.
    // Until it's available, we use ttl of the containing key as follows.
    const [ bool, ttl ] = await Promise.all([
      redisData.hexists(dbKey, field),
      redisData.ttl(dbKey)
    ])
    return {ttl: bool ? ttl : 0};
}

// Plumbs defunct pipes with bodyless http-requests under timeout
function plumbDefunctPipes(tokens, receive=true){
  if (Boolean(tokens?.length) === false) return;
  const method = receive ? "POST" : "GET";
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
// Timestamps (Unix-time in seconds) are stored with the tokens using string concatenation.
export async function pipeToPublic(privateKey, receive=true){
  const publicKey = genPublicKey(privateKey);
  const mode = receive ? "receive" : "send";
  const dbKey = dbKeyPrefix.pipe[mode] + parseKey(publicKey, { validate: false }).random;
  const token = randStr();
  const timeNow = Math.round(Date.now()/1000);
  const [ count, ] = await Promise.all([
    redisData.lpush(dbKey, token + '@' + timeNow),
    redisData.expire(dbKey, streamTimeout)
  ])
  if (count > maxStreamCount) {
    const expiredTokens = await redisData.rpop(dbKey, count - maxStreamCount);
    plumbDefunctPipes(expiredTokens);
  }
  return pipingServerURL + token;
}

// Expired, unused tokens imply defunct pipes (see above).
export async function pipeToPrivate(publicKey, receive=true){
  const privateMode = receive ? "send" : "receive";
  const dbKey = dbKeyPrefix.pipe[privateMode] + parseKey(publicKey).random;
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
      plumbDefunctPipes([token+'@'+timestamp,...expiredTokens]);
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
export async function OneSignalSendPush(app, externalID, data=null){
  const OneSignalAPIKey = OneSignalKey(app);
  const OneSignalAppID = OneSignalID(app);
  const appObj = await fetch(`https://securelay.github.io/apps/${app.toLowerCase()}.json`)
    .then((response) => response.json())
    .catch((err) => undefined);
  if(!appObj.webPush.data) delete data.data; // Delete private data from payload for security
  if (! (OneSignalAPIKey && OneSignalAppID && appObj)) throw new Error('App is not recognized');
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

// Push JSON (object) to be stored at https://securelay.github.io/jsonbin/{id}/{publicKey}.json
// The function adds metadata using decoratePayload() above.
// Do not pass JSON in order to touch existing data (i.e. update its timestamp).
// Pass null as `json` and true as `remove` for removing the stored data.
// Returns true if data is updated or deleted, false otherwise.
// Ref: https://github.com/octokit/plugin-create-or-update-text-file.js/
export async function githubPushJSON(privateKey, json=null, remove=false){
  const publicKey = genPublicKey(privateKey);
  const path = id() + '/' + publicKey + '.json';
  const touch = Boolean(!(json || remove));
  const timeNow = Math.round(Date.now()/1000); // Unix-time in seconds
  let content, mode;
  
  if (touch) {
    // Do not commit to GitHub if re-touching within a day. Because CDN_TTL >> 1 day.
    // Avoiding GitHub traffic reduces blocking time, thus helping performance.
    const lastTouched = await cacheGet(publicKey, 'cdnRenewed');
    if (lastTouched && ((timeNow - lastTouched) < 86400)) return true;
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
  
  const { updated, deleted } = await octokit.createOrUpdateTextFile({
    owner: "securelay",
    repo: "jsonbin",
    path: path,
    content: content,
    message: mode + ' ' + path,
  });

  if (mode === 'deleted') {
    await cacheDel(privateKey, 'cdnRenewed');
    return deleted;
  } else {
    await cacheSet(privateKey, { cdnRenewed: timeNow });
    return updated && !deleted; // updated and deleted both being truthy means expiry
  }
}
