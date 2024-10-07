import * as helper from './helper.js';
import Fastify from 'fastify';

const bodyLimit = parseInt(process.env.BODYLIMIT);
const fieldLimit = parseInt(process.env.FIELDLIMIT);

// Impose content-length limit
const fastify = Fastify({
  ignoreTrailingSlash: true,
  bodyLimit: bodyLimit
})

// Enable CORS. This implementation is lightweight than importing '@fastify/cors'
fastify.addHook('onRequest', (request, reply, done) => {
    reply.headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST'
    })
    done();
})

// Enable parser for application/x-www-form-urlencoded
fastify.register(import('@fastify/formbody'))

const callUnauthorized = function(reply, msg){
    reply.code(401).send({message: msg, error: "Unauthorized", statusCode: reply.statusCode});
}

const callBadRequest = function(reply, msg){
    reply.code(400).send({message: msg, error: "Bad Request", statusCode: reply.statusCode});
}

const callInternalServerError = function(reply, msg){
    reply.code(500).send({message: msg, error: "Internal Server Error", statusCode: reply.statusCode});
}

fastify.get('/', (request, reply) => {
    reply.redirect('https://securelay.github.io', 301);
})

fastify.post('/', (request, reply) => {
    reply.redirect('https://securelay.github.io', 301);
})

fastify.get('/keys', (request, reply) => {
    reply.send(helper.genKeyPair());
})

fastify.get('/keys/:key', (request, reply) => {
    const { key } = request.params;
    const keyType = helper.validate(key);
    if (keyType === 'public') {
        reply.send({type: "public"});
    } else if (keyType === 'private') {
        reply.send({type: "private", public: helper.genPublicKey(key)});
    } else {
        reply.callNotFound();
    }
})

fastify.post('/public/:publicKey', async (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        await helper.publicProduce(publicKey, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        const dataArray = await helper.privateConsume(privateKey);
        if (!dataArray.length) throw 404;
        reply.send(dataArray);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.post('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        await helper.privateProduce(privateKey, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/public/:publicKey', async (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        const data = await helper.publicConsume(publicKey);
        if (!data) throw 404;
        reply.send(data);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.post('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    if (key.substr(0,fieldLimit) !== key) {callBadRequest(reply, 'Provided field is too long'); return;}
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        await helper.oneToOneProduce(privateKey, key, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/public/:publicKey/:key', async (request, reply) => {
    const { publicKey, key } = request.params;
    if (key.substr(0,fieldLimit) !== key) {callBadRequest(reply, 'Provided field is too long'); return;}
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        const data = await helper.oneToOneConsume(publicKey, key);
        if (!data) throw 404;
        reply.send(data);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    if (key.substr(0,fieldLimit) !== key) {callBadRequest(reply, 'Provided field is too long'); return;}
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        reply.send(await helper.oneToOneIsConsumed(privateKey, key));
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
