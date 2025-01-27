import * as helper from './helper.js';
import Fastify from 'fastify';

const endpointID = helper.id();
const bodyLimit = parseInt(process.env.BODYLIMIT);
const fieldLimit = parseInt(process.env.FIELDLIMIT);
const webhookTimeout = parseInt(process.env.WEBHOOK_TIMEOUT);

// Impose content-length limit
const fastify = Fastify({
  ignoreTrailingSlash: true,
  bodyLimit: bodyLimit
})

// Enable CORS. This implementation is lightweight than importing '@fastify/cors'
fastify.addHook('onRequest', (request, reply, done) => {
    reply.headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE'
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

fastify.get('/id', (request, reply) => {
    const app = request.query.app;
    if (app == null) {
      reply.send(endpointID);
    } else {
      const OneSignalID = helper.OneSignalID(app);
      if (OneSignalID) {
        reply.send(OneSignalID);
      } else {
        reply.callNotFound();
      }
    }
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
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;

    try {
        if (helper.validate(publicKey) !== 'public') throw 401;

        const app = request.query.app;
        const data = helper.decoratePayload(request.body);
        let webhookUsed = false;

        // Try posting the data to webhook, if any, with timeout. On fail, store/bin data for later retrieval.
        try {
            const webhook = await helper.cacheGet(publicKey, 'hook');
            if (!webhook) throw new Error('No webhook');
            
            await fetch(webhook, {
                method: "POST",
                redirect: "follow",
                headers: { "Content-type": "application/json" },
                body: JSON.stringify(data),
                signal: AbortSignal.timeout(webhookTimeout)
            }).then((response) => {
                if (! response.ok) throw new Error(response.status);
                return response.text();
            })
            
            webhookUsed = true;
        } catch (err) {
            await Promise.all([
              helper.publicProduce(publicKey, data),
              helper.cacheDel(publicKey, 'hook')
            ])
        }
        
        if (app) await helper.OneSignalSendPush(app, publicKey, {webhook: webhookUsed, data: data}).catch((err) => {});

        if (redirectOnOk == null) {
            reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode, webhook: webhookUsed});
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err == 401) {
                callUnauthorized(reply, 'Provided key is not Public');
            } else {
                callInternalServerError(reply, err);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }
})

fastify.get('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const webhook = request.query.hook;
    const statsPresent = 'stats' in request.query;

    let webhookHandler, statsHandler, dataHandler;
    webhookHandler = statsHandler = dataHandler = () => null; // default

    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        if (webhook == null) {
            webhookHandler = () => helper.cacheDel(privateKey, 'hook');
        } else {
            webhookHandler = () => helper.cacheSet(privateKey, {hook:webhook});
        }
        if (statsPresent) {
          statsHandler = () => helper.privateStats(privateKey);
        } else {
          dataHandler = () => helper.privateConsume(privateKey);
        }
        
        const [ _, statsObj, dataArray ] = await Promise.all([
          webhookHandler(),
          statsHandler(),
          dataHandler()
        ])
        
        if (statsPresent) return statsObj;
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
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        //await helper.privateProduce(privateKey, JSON.stringify(helper.decoratePayload(request.body)));
        if (! await helper.githubPushJSON(privateKey, request.body)) throw 500;
        if (redirectOnOk == null) {
            reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err == 401) {
                callUnauthorized(reply, 'Provided key is not Private');
            } else {
                callInternalServerError(reply, err);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.delete('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        //await helper.privateDelete(privateKey);
        if (! await helper.githubPushJSON(privateKey, null, true)) throw 500;
        reply.code(204);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }
})

fastify.patch('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        //await helper.privateRefresh(privateKey);
        if (! await helper.githubPushJSON(privateKey)) throw 500;
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
        //const data = await helper.publicConsume(publicKey);
        //if (!data) throw 404;
        //reply.send(data);
        reply.redirect(`https://securelay.github.io/jsonbin/${endpointID}/${publicKey}.json`, 301);
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
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (key.substr(0,fieldLimit) !== key) throw 400;
        if (helper.validate(privateKey) !== 'private') throw 401;
        await helper.oneToOneProduce(privateKey, key, JSON.stringify(helper.decoratePayload(request.body)));
        if (redirectOnOk == null) {
            reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err == 400) {
                callBadRequest(reply, 'Provided field is too long');
            } else if (err == 401) {
                callUnauthorized(reply, 'Provided key is not Private');
            } else {
                callInternalServerError(reply, err);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.get('/public/:publicKey/:key', async (request, reply) => {
    const { publicKey, key } = request.params;
    try {
        if (key.substr(0,fieldLimit) !== key) throw 400;
        if (helper.validate(publicKey) !== 'public') throw 401;
        const data = await helper.oneToOneConsume(publicKey, key);
        if (!data) throw 404;
        reply.send(data);
    } catch (err) {
        if (err == 400) {
            callBadRequest(reply, 'Provided field is too long');
        } else if (err == 401) {
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
    try {
        if (key.substr(0,fieldLimit) !== key) throw 400;
        if (helper.validate(privateKey) !== 'private') throw 401;
        return helper.oneToOneTTL(privateKey, key);
    } catch (err) {
        if (err == 400) {
            callBadRequest(reply, 'Provided field is too long');
        } else if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

const streamHandler = async (request, reply) => {
  const { key } = request.params;
  try {
    let recvBool;
    switch (request.method) {
      case 'POST': // Using fallthrough! POST and PUT cases run the same code.
      case 'PUT':
        recvBool = false;
        break;
      case 'GET':
        recvBool = true;
        break;
      default:
        throw new Error('Unsupported Method');
    }
    const token = await helper.streamToken(key, recvBool);
    reply.redirect('https://ppng.io/' + token, 307);
  } catch (err) {
    if (err.message == 'Invalid Key') {
      callUnauthorized(reply, 'Provided key is invalid');
    } else if (err.message == 'Unsupported Method') {
      callBadRequest(reply, 'Unsupported method');
    } else {
      callInternalServerError(reply, err);
    }
  }
}

fastify.all('/stream/:key', streamHandler);

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
