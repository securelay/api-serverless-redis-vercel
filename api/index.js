import * as helper from './helper.js';
import Fastify from 'fastify';

const endpointID = helper.id();
const cdnUrlBase = `https://cdn.jsdelivr.net/gh/securelay/jsonbin@main/${endpointID}`;
//const cdnUrlBase = `https://securelay.github.io/jsonbin/${endpointID}`;
//const cdnUrlBase = `https://raw.githubusercontent.com/securelay/jsonbin/main/${endpointID}`;

const bodyLimit = parseInt(process.env.BODYLIMIT);
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

const callForbidden = function(reply, msg){
    reply.code(403).send({message: msg, error: "Forbidden", statusCode: reply.statusCode});
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
    try {
      const publicKey = helper.genPublicKey(key); // Also validates, even if key is public!
      const type = helper.parseKey(key).type;
      reply.send( { type: type, public: publicKey } );
    } catch (err) {
      if (err.message === 'Invalid Key') {
        callBadRequest(reply, 'Provided key is invalid');
      } else {
        callInternalServerError(reply, err.message);
      }
    }
})

fastify.post('/public/:publicKey', async (request, reply) => {
    const { publicKey } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;

    try {
        if (helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');

        const webhook = await helper.cacheGet(publicKey, 'hook'); // Also validates key
        let webhookUsed = false;

        const app = request.query.app;
        const data = helper.decoratePayload(request.body);

        // Try posting the data to webhook, if any, with timeout. On fail, store/bin data for later retrieval.
        try {
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
            if (err.message == 'Unauthorized') {
                callUnauthorized(reply, 'Provided key is not Public');
            } else if (err.message === 'Invalid Key') {
                callBadRequest(reply, 'Provided key is invalid');
            } else {
                callInternalServerError(reply, err.message);
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
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
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
        if (!dataArray.length) throw new Error('No Data');
        reply.send(dataArray);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err.message);
        }
    }    
})

fastify.post('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    const passwd = request.query.password;
    try {
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        const cdn = {};
        if (passwd == null) {
          if (! await helper.githubPushJSON(privateKey, request.body)) throw new Error('Push to GitHub CDN failed');
          cdn['cdn'] = `${cdnUrlBase}/${helper.genPublicKey(privateKey)}.json`;
        } else {
          const data = JSON.stringify(helper.decoratePayload(request.body, {}, passwd));
          await helper.privateProduce(privateKey, data);
        }

        if (redirectOnOk == null) {
            reply.send({
              message: "Done",
              error: "Ok",
              statusCode: reply.statusCode,
              ...cdn
            });
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                callUnauthorized(reply, 'Provided key is not Private');
            } else if (err.message === 'Invalid Key') {
                callBadRequest(reply, 'Provided key is invalid');
            } else {
                callInternalServerError(reply, err.message);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.delete('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const passwdPresent = 'password' in request.query;
    try {
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        if (passwdPresent) {
          await helper.privateDelete(privateKey);
        } else {
          if (! await helper.githubPushJSON(privateKey, null, true)) throw new Error('Push to GitHub CDN failed');
        }
        reply.code(204);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else {
            callInternalServerError(reply, err.message);
        }
    }
})

fastify.patch('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const passwdPresent = 'password' in request.query;
    try {
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        const cdn = {};
        if (passwdPresent) {
          await helper.privateRefresh(privateKey);
        } else {
          if (! await helper.githubPushJSON(privateKey)) throw new Error('Push to GitHub CDN failed');
          cdn['cdn'] = `${cdnUrlBase}/${helper.genPublicKey(privateKey)}.json`;
        }

        reply.send({
          message: "Done",
          error: "Ok",
          statusCode: reply.statusCode,
          ...cdn
        });
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else {
            callInternalServerError(reply, err.message);
        }
    }
})

fastify.get('/public/:publicKey', async (request, reply) => {
    const { publicKey } = request.params;
    const passwd = request.query.password;
    try {
        if (helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');
        
        if (passwd == null) {
          reply.redirect(`${cdnUrlBase}/${publicKey}.json`, 301);
        } else {
          const data = await helper.publicConsume(publicKey);
          if (!data) throw new Error('No Data');
          const unlockedData = helper.unlockJSON(data, passwd);
          if (!unlockedData) throw new Error('Unlock Failed');
          reply.send(unlockedData);
        }
        
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'Unlock Failed') {
            callForbidden(reply, 'Provided password is wrong');
        } else if (err.message === 'No Data') {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err.message);
        }
    }    
})

fastify.post('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        await helper.oneToOneProduce(privateKey, key, JSON.stringify(helper.decoratePayload(request.body)));
        if (redirectOnOk == null) {
            reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                callUnauthorized(reply, 'Provided key is not Private');
            } else if (err.message === 'Invalid Key') {
                callBadRequest(reply, 'Provided key is invalid');
            } else {
                callInternalServerError(reply, err.message);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.get('/public/:publicKey/:key', async (request, reply) => {
    const { publicKey, key } = request.params;
    try {
        if (helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');
        const data = await helper.oneToOneConsume(publicKey, key);
        if (!data) throw new Error('No Data');
        reply.send(data);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err.message);
        }
    }    
})

fastify.get('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    try {
        if (helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        return helper.oneToOneTTL(privateKey, key);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else {
            callInternalServerError(reply, err.message);
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
      callBadRequest(reply, 'Provided key is invalid');
    } else if (err.message == 'Unsupported Method') {
      callBadRequest(reply, 'Unsupported method');
    } else {
      callInternalServerError(reply, err.message);
    }
  }
}

fastify.all('/stream/:key', streamHandler);

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
