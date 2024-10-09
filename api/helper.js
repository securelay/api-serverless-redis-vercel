import Crypto from 'node:crypto';
import { kv } from '@vercel/kv';

const secret = process.env.SECRET;
const sigLen = parseInt(process.env.SIG_LEN);
const hashLen = parseInt(process.env.HASH_LEN);
const ttl = parseInt(process.env.TTL);
const dbKeyPrefix = {
                manyToOne: "m2o:",
                oneToMany: "o2m:",
                oneToOne: "o2o:",
            }

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

export function genPublicKey(privateKey){
    const privateHash = privateKey.substr(sigLen,);
    const publicHash = hash(privateHash);
    const publicKey = sign(publicHash + 'public') + publicHash;
    return publicKey
}

export function genKeyPair(seed = Crypto.randomUUID()){
    const privateHash = hash(seed);
    const privateKey = sign(privateHash + 'private') + privateHash;
    const publicKey = genPublicKey(privateKey);
    return {private: privateKey, public: publicKey};
}

export async function publicProduce(publicKey, data){
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    return kv.rpush(dbKey, data).then(kv.expire(dbKey, ttl));
}

export async function privateConsume(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.manyToOne + publicKey;
    const llen = await kv.llen(dbKey);
    if (!llen) return [];
    return kv.lpop(dbKey, llen);
}

export async function privateProduce(privateKey, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return kv.set(dbKey, data, { ex: ttl });
}

export async function privateDelete(privateKey){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return kv.del(dbKey);
}

export async function publicConsume(publicKey){
    const dbKey = dbKeyPrefix.oneToMany + publicKey;
    return kv.get(dbKey);
}

export async function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    let field = {};
    field[key] = data;
    return kv.hset(dbKey, field).then(kv.expire(dbKey, ttl));
}

export async function oneToOneConsume(publicKey, key){
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    return kv.hget(dbKey, field).then(kv.hdel(dbKey, field));
}

export async function oneToOneIsConsumed(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const dbKey = dbKeyPrefix.oneToOne + publicKey;
    const field = key;
    const bool = await kv.hexists(dbKey, field);
    if (bool) {
        return "Not consumed yet.";
    } else {
        return "Consumed.";
    }
}
