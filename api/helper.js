/*
Refs:
https://upstash.com/docs/redis/sdks/ts/pipelining/pipeline-transaction
https://upstash.com/docs/redis/sdks/ts/pipelining/auto-pipeline
*/
import { hash as cryptoHash, createHmac, getRandomValues, randomUUID } from 'node:crypto';
import { Buffer } from "node:buffer";
import { Redis } from '@upstash/redis';

const secret = process.env.SECRET;
const sigLen = parseInt(process.env.SIG_LEN);
const hashLen = parseInt(process.env.HASH_LEN);
const ttl = parseInt(process.env.TTL);
const cacheTtl = parseInt(process.env.CACHE_TTL);
const dbKeyPrefix = {
                manyToOne: "m2o:",
                oneToMany: "o2m:",
                oneToOne: "o2o:",
                cache: "cache:"
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

function hash(str){
    return cryptoHash('md5', str, 'base64url').substring(0,hashLen);
    // For small size str crypto.hash() is faster than crypto.createHash()
    // Ref: https://nodejs.org/api/crypto.html#cryptohashalgorithm-data-outputencoding
}

function sign(str){
    // Ref: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
    return createHmac('md5', secret).update(str).digest('base64url').substring(0,sigLen);
}

//Brief: Return random base64url string of given length
function randStr(len = hashLen){
  const byteSize = Math.ceil(len*6/8);
  const buff = Buffer.alloc(byteSize);
  getRandomValues(buff);
  return buff.toString('base64url').substring(0,len);
}

export function id(){
    return sign('id');
}

export function validate(key){
    const sig = key.substring(0, sigLen);
    const hash = key.substring(sigLen);
    if (sig === sign(hash + 'public')){
        return 'public';
    } else if (sig === sign(hash + 'private')){
        return 'private';
    } else {
        return false;
    }
}

export function genPublicKey(privateOrPublicKey){
    if (validate(privateOrPublicKey) === 'public') return privateOrPublicKey;
    const privateKey = privateOrPublicKey;
    const privateHash = privateKey.substring(sigLen);
    const publicHash = hash(privateHash);
    const publicKey = sign(publicHash + 'public') + publicHash;
    return publicKey;
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

export function genKeyPair(seed = randomUUID()){
    const privateHash = hash(seed);
    const privateKey = sign(privateHash + 'private') + privateHash;
    const publicKey = genPublicKey(privateKey);
    return {private: privateKey, public: publicKey};
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
    const [ countConsume, ttlConsume, ttlPublish ] = await Promise.all([
      redisData.llen(dbKeyConsume),
      redisData.ttl(dbKeyConsume),
      redisData.ttl(dbKeyPublish)
    ])
    return {
      consume: {
        count: countConsume,
        ttl: ttlConsume < 0 ? 0 : ttlConsume
        },
      publish: {
        ttl: ttlPublish < 0 ? 0 : ttlPublish
        }
      };
}

export async function publicConsume(publicKey){
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return redisData.get(dbKey);
}

export async function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    let field = {};
    field[key] = data;
    return Promise.all([
      redisData.hset(dbKey, field),
      redisData.expire(dbKey, ttl)
    ])
}

export async function oneToOneConsume(publicKey, key){
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    const atomicTransaction = redisData.multi();
    atomicTransaction.hget(dbKey, field);
    atomicTransaction.hdel(dbKey, field);
    return atomicTransaction.exec()
      .then((values) => values[0]);
}

export async function oneToOneTTL(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    const [ bool, ttl ] = await Promise.all([
      redisData.hexists(dbKey, field),
      redisData.ttl(dbKey)
    ])
    return {ttl: bool ? ttl : 0};
}
