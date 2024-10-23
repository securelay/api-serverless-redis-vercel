import Crypto from 'node:crypto';
import { createClient } from '@vercel/kv';

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
const redisData = createClient({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})
// Redis client for ratelimiter database
const redisRateLimit = createClient({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
})

function hash(str){
    return Crypto.hash('md5', str, 'base64url').substr(0,hashLen);
    // For small size str Crypto.hash() is faster than Crypto.createHash()
}

function sign(str){
    // Note: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
    return Crypto.createHmac('md5', secret).update(str).digest('base64url').substr(0,sigLen);
}

export function id(){
    return sign('id');
}

export function validate(key){
    const sig = key.substr(0, sigLen);
    const hash = key.substr(sigLen,);
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
    const privateHash = privateKey.substr(sigLen,);
    const publicHash = hash(privateHash);
    const publicKey = sign(publicHash + 'public') + publicHash;
    return publicKey;
}

export function cacheSet(privateKey, obj){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.cache + publicKey;
    return redisRateLimit.hset(dbKey, obj).then(redisRateLimit.expire(dbKey, cacheTtl));
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

export function genKeyPair(seed = Crypto.randomUUID()){
    const privateHash = hash(seed);
    const privateKey = sign(privateHash + 'private') + privateHash;
    const publicKey = genPublicKey(privateKey);
    return {private: privateKey, public: publicKey};
}

export async function publicProduce(publicKey, data){
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    return redisData.rpush(dbKey, data).then(redisData.expire(dbKey, ttl));
}

export async function privateConsume(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    const llen = await redisData.llen(dbKey);
    if (!llen) return [];
    return redisData.lpop(dbKey, llen);
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

export async function publicConsume(publicKey){
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return redisData.get(dbKey);
}

export async function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    let field = {};
    field[key] = data;
    return redisData.hset(dbKey, field).then(redisData.expire(dbKey, ttl));
}

export async function oneToOneConsume(publicKey, key){
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    return redisData.hget(dbKey, field).then(redisData.hdel(dbKey, field));
}

export async function oneToOneIsConsumed(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    const bool = await redisData.hexists(dbKey, field);
    if (bool) {
        return "Not consumed yet.";
    } else {
        return "Consumed.";
    }
}
