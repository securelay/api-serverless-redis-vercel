import Crypto from 'node:crypto';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { mkdirp } from 'mkdirp';
import {rimraf} from 'rimraf';

const secret = process.env.SECRET;
const sigLength = parseInt(process.env.SIG_LENGTH);
const expiry = parseInt(process.env.EXPIRY);
const dbRoot = tmpdir() + process.env.DBROOT;

const dir = {
                manyToOne: dbRoot + "/manyToOne/", 
                oneToMany: dbRoot + "/oneToMany/", 
                oneToOne: dbRoot + "/oneToOne/", 
                tmp: dbRoot + "/tmp/"
            }

function hash(str){
    return Crypto.hash('sha256', str, 'base64url'); // For small size str this is faster than fs.createHash()
}

function sign(str){
    // Note: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
    return Crypto.createHmac('sha256', secret).update(str).digest('base64url').substr(0,sigLength);
}

export function validate(key){
    const sig = key.substr(0, sigLength);
    const hash = key.substr(sigLength,);
    if (sig === sign(hash + 'public')){
        return 'public';
    } else if (sig === sign(hash + 'private')){
        return 'private';
    } else {
        return false;
    }
}

export function genPublicKey(privateKey){
    const privateHash = privateKey.substr(sigLength,);
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

export function setupDB(){
    for (const key in dir) {
        mkdirp.sync(dir[key]);
    }
}

export function publicProduce(publicKey, data){
    const destDir = dir.manyToOne + publicKey + '/';
    const uuid = Crypto.randomUUID();
    const tmpfile = dir.tmp + uuid;
    fs.writeFileSync(tmpfile, data, {flush: true});
    mkdirp.sync(destDir);
    fs.renameSync(tmpfile, destDir + uuid);
}

export function privateConsume(privateKey){
    const publicKey = genPublicKey(privateKey);
    const srcDir = dir.manyToOne + publicKey + '/';
    if (!fs.existsSync(srcDir)) return [];
    let aggregatedDataAsArray = [];
    for (const file of fs.readdirSync(srcDir)) {
        const data = fs.readFileSync(srcDir + file, 'utf8'); 
        aggregatedDataAsArray.push(data);
        fs.unlinkSync(srcDir + file);
    }
    return aggregatedDataAsArray;
}

export function privateProduce(privateKey, data){
    const publicKey = genPublicKey(privateKey);
    const tmpfile = dir.tmp + Crypto.randomUUID();
    fs.writeFileSync(tmpfile, data, {flush: true});
    fs.renameSync(tmpfile, dir.oneToMany + publicKey);
}

export function publicConsume(publicKey){
    const srcFile = dir.oneToMany + publicKey;
    if (!fs.existsSync(srcFile)) return;    
    return fs.readFileSync(srcFile, 'utf8');
}

export function oneToOneProduce(privateKey, key, data){
    const publicKey = genPublicKey(privateKey);
    const destDir = dir.oneToOne + publicKey + '/';
    mkdirp.sync(destDir);
    const tmpfile = dir.tmp + Crypto.randomUUID();
    fs.writeFileSync(tmpfile, data, {flush: true});
    fs.renameSync(tmpfile, destDir + hash(key));    
}

export function oneToOneConsume(publicKey, key){
    const srcFile = dir.oneToOne + publicKey + '/' + hash(key)
    if (!fs.existsSync(srcFile)) return;
    const data = fs.readFileSync(srcFile, 'utf8');
    fs.unlinkSync(srcFile);
    return data;
}

export function oneToOneIsConsumed(privateKey, key){
    const publicKey = genPublicKey(privateKey);
    const srcFile = dir.oneToOne + publicKey + '/' + hash(key);
    return !fs.existsSync(srcFile);
}

function isExpired(path){
    const age = (new Date().getTime() - fs.statSync(path).mtime) / 1000;
    return age > expiry;
}

function gcIn(dir){
    rimraf(dir + '/**/*', {glob: true, filter: isExpired}).then((val) => {console.log(`Garbage cleaned in ${dir}`);}, (err) => {console.log(err.data);});
}

export function gc(){
    for (const key in dir) {
        gcIn(dir[key]);
    }
}
