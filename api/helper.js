/*
Refs:
https://upstash.com/docs/redis/sdks/ts/pipelining/pipeline-transaction
https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
*/
import { hash as cryptoHash, createHmac, getRandomValues, randomUUID } from 'node:crypto';
import { Buffer } from "node:buffer";
import { Redis } from '@upstash/redis';
import { Octokit } from '@octokit/core';
import { createOrUpdateTextFile } from '@octokit/plugin-create-or-update-text-file';

const secret = process.env.SECRET;
const sigLen = parseInt(process.env.SIG_LEN);
const hashLen = parseInt(process.env.HASH_LEN);
const ttl = parseInt(process.env.TTL);
const cacheTtl = parseInt(process.env.CACHE_TTL);
const streamTimeout = parseInt(process.env.STREAM_TIMEOUT);
const maxStreamCount = parseInt(process.env.MAX_STREAM_COUNT);

const dbKeyPrefix = {
                manyToOne: "m2o:",
                oneToMany: "o2m:",
                oneToOne: "o2o:",
                cache: "cache:",
                stream: {
                  public: {
                    send: "pipePubSend:",
                    receive: "pipePubRecv:"
                  },
                  private: {
                    send: "pipePrivSend:",
                    receive: "pipePrivRecv:"
                  }
                }
            }

// Redis client for user database
const redisData = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
  latencyLogging: false,
  enableAutoPipelining: true
})
// Redis client for ratelimiter database
const redisRateLimit = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
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

// Check if given key is valid, and if it is, return its type
export function validate(key, silent=true){
    const sig = key.substring(0, sigLen);
    const hash = key.substring(sigLen);
    if (sig === sign(hash + 'public')){
        return 'public';
    } else if (sig === sign(hash + 'private')){
        return 'private';
    } else {
        if (!silent) throw new Error('Invalid Key');
        return false;
    }
}

// Assert if given key is of the given type (private | public)
// This is computationally favorable to the Boolean: validate(key) === type
export function assert(key, type){
    const sig = key.substring(0, sigLen);
    const hash = key.substring(sigLen);
    return sig === sign(hash + type);
}

export function genPublicKey(privateOrPublicKey){
    if (assert(privateOrPublicKey, 'public')) return privateOrPublicKey;
    const privateKey = privateOrPublicKey;
    const privateHash = privateKey.substring(sigLen);
    const publicHash = hash(privateHash);
    const publicKey = sign(publicHash + 'public') + publicHash;
    return publicKey;
}

export function genKeyPair(seed = randomUUID()){
    const privateHash = hash(seed);
    const privateKey = sign(privateHash + 'private') + privateHash;
    const publicKey = genPublicKey(privateKey);
    return {private: privateKey, public: publicKey};
}

export function cacheSet(privateKey, obj){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.cache + publicKey;
    // Promise.all below enables both commands to be executed in a single http request (using same pipeline)
    // As Redis is single-threaded, the commands are executed in order
    // See https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
    return Promise.all([
      redisRateLimit.hset(dbKey, obj),
      redisRateLimit.expire(dbKey, cacheTtl)
    ])
}

export function cacheGet(publicKey, key){
    const dbKey = dbKeyPrefix.cache + publicKey;
    return redisRateLimit.hget(dbKey, key);
}

export function cacheDel(privateOrPublicKey, key){
    const publicKey = genPublicKey(privateOrPublicKey);
    const dbKey = dbKeyPrefix.cache + publicKey;
    return redisRateLimit.hdel(dbKey, key);
}

// Add metadata to payload (which must be a JSON object)
// Some metadata, such as `id` to uniquely identify a payload and timestamp, are generated
// Other metadata may be provided as the `fields` JSON object.
// `passwd`, if provided, is hashed and stored as metadata property `__lock__`.
export function decoratePayload(payload, fields={}, passwd=null){
  const generatedMeta = {id: randStr(), time: Date.now()};
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
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    return Promise.all([
      redisData.rpush(dbKey, data),
      redisData.expire(dbKey, ttl)
    ])
}

export async function privateConsume(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    const atomicTransaction = redisData.multi();
    atomicTransaction.lrange(dbKey, 0, -1);
    atomicTransaction.del(dbKey);
    return atomicTransaction.exec()
      .then((values) => values[0]);
}

export async function privateProduce(privateKey, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return redisData.set(dbKey, data, { ex: ttl });
}

export async function privateDelete(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return redisData.del(dbKey);
}

export async function privateRefresh(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return redisData.expire(dbKey, ttl);
}

export async function privateStats(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKeyConsume = dbKeyPrefix.manyToOne + publicKey;
    const dbKeyPublish = dbKeyPrefix.oneToMany + publicKey;
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
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    // Ideally there should be getex() in Upstash's Redis SDK.
    // Until it's available, we make do with pipelining as follows.
    const [ data, _ ] = await Promise.all([
      redisData.get(dbKey),
      redisData.expire(dbKey, ttl)
    ])
    return data;
}

export async function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = {[hash(key)]: data};
    return Promise.all([
      redisData.hset(dbKey, field),
      redisData.expire(dbKey, ttl)
    ])
}

export async function oneToOneConsume(publicKey, key){
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = hash(key);
    const atomicTransaction = redisData.multi();
    atomicTransaction.hget(dbKey, field);
    atomicTransaction.hdel(dbKey, field);
    return atomicTransaction.exec()
      .then((values) => values[0]);
}

export async function oneToOneTTL(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = hash(key);
    const [ bool, ttl ] = await Promise.all([
      redisData.hexists(dbKey, field),
      redisData.ttl(dbKey)
    ])
    return {ttl: bool ? ttl : 0};
}

// Tokens are stored in LIFO stacks. Old and unused tokens are trimmed.
export async function streamToken(privateOrPublicKey, receive=true){
  const type = validate(privateOrPublicKey, false);
  const typeComplement = (type == 'private') ? 'public' : 'private';
  const publicKey = genPublicKey(privateOrPublicKey);
  const mode = receive ? "receive" : "send";
  const modeComplement = receive ? "send" : "receive";
  const existing = await redisData.lpop(dbKeyPrefix.stream[typeComplement][modeComplement] + publicKey);
  const timeNow = Math.round(Date.now()/1000);
  if (existing) {
    const [token, timestamp] = existing.split('@');
    // Expired unused tokens are possible as adding new tokens refreshes the expiry of the entire list (see below).
    // Return token that is not expired.
    if ((timeNow - timestamp) < streamTimeout) return token;
  }
  const token = randStr();
  const dbKey = dbKeyPrefix.stream[type][mode] + publicKey;
  await Promise.all([
    redisData.lpush(dbKey, token + '@' + timeNow),
    redisData.expire(dbKey, streamTimeout),
    redisData.ltrim(dbKey, 0, maxStreamCount - 1)
  ])
  return token;
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
    .catch((err) => null);
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
  let content, mode;
  
  if (touch) {
    // Just update timestamp in metadata when `touch` is true;
    mode = 'touched';
    content = ({exists, content}) => {
      if (!exists) return null;
      const json = JSON.parse(content);
      json.time = Date.now();
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

  return updated || deleted;
}
