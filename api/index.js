import * as helper from './_utils.js';
import Fastify from 'fastify';
import { waitUntil } from '@vercel/functions';

// Impose content-length limit
const fastify = Fastify({
  ignoreTrailingSlash: true,
  bodyLimit: parseInt(process.env.BODYLIMIT)
})

// Enable CORS. This implementation is lightweight than importing '@fastify/cors'
fastify.addHook('onRequest', (request, reply, done) => {
    reply.headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'HEAD,GET,POST,PATCH,DELETE',
        'Content-Disposition': 'inline'
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

const callConflict = function(reply, msg){
    reply.code(409).send({message: msg, error: "Conflict", statusCode: reply.statusCode});
}

const callInsufficientStorage = function(reply, msg){
    reply.code(507).send({message: msg, error: "Insufficient Storage", statusCode: reply.statusCode});
}

const callMethodNotAllowed = function(reply, allowedMethods, msg){
    reply.code(405)
      .header('Allow', allowedMethods)
      .send({message: msg, error: "Method Not Allowed", statusCode: reply.statusCode});
}

fastify.get('/keys', async (request, reply) => {
    reply.send(await helper.genKeyPair());
})

fastify.get('/keys/:key', async (request, reply) => {
    const { key } = request.params;
    try {
      const publicKey = await helper.genPublicKey(key); // Also validates, even if key is public!
      const type = await helper.parseKey(key, { validate: false }).type;
      reply.send( { type: type, public: publicKey } );
    } catch (err) {
      if (err.message === 'Invalid Key') {
        callBadRequest(reply, 'Provided key is invalid');
      } else {
        callInternalServerError(reply, err.message);
      }
    }
})

fastify.post('/public/:publicKey/:channel?', async (request, reply) => {
    const { publicKey, channel } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    let payload = request.body;
    try {
        if (await helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');

        const webhook = await helper.cacheGet(publicKey, 'hook'); // Also validates key

        const app = request.query.app;

        const meta =  {};
        const { 
          'x-vercel-ip-country': country,
          'x-vercel-ip-country-region': region,
          'x-vercel-ip-city': city,
          'x-real-ip': ip,
          'content-length': bodySize
        } = request.headers;
        if (country || region || city) meta.geolocation = [country, region, city].join('/');
        if (ip) meta.ip = ip;
        if (channel) {
          meta.channel = channel;
          // If request doesn't have a body, use the value stored in channel(key) instead
          if (parseInt(bodySize) === 0) {
            const channelData = await helper.oneToOneConsume(publicKey, channel);
            payload = channelData?.data ?? {};
          }
        }
        const data = helper.decoratePayload(payload, meta);

        // Try posting the data to webhook, if any, with timeout.
        // On fail, store data and send web-push notifications to owner.
        try {
            if (!webhook) throw new Error('No webhook');
            data.webhook = true; // Data passed via webhook should also have webhook-usage metadata
            
            const webhookTimeout = parseInt(process.env.WEBHOOK_TIMEOUT);
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
            
        } catch (err) {
            data.webhook = false;
            await helper.publicProduce(publicKey, data);
            if (webhook) waitUntil(helper.cacheDel(publicKey, 'hook').catch((err) => {}));
            if (app) waitUntil(helper.OneSignalSendPush(app, publicKey, data).catch((err) => {}));
        }

        if (redirectOnOk == null) {
            reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode, webhook: data.webhook});
        } else {
            reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                callUnauthorized(reply, 'Provided key is not Public');
            } else if (err.message === 'Invalid Key') {
                callBadRequest(reply, 'Provided key is invalid');
            } else if (err.message === 'No Payload') {
                callBadRequest(reply, 'No data provided in the request body');
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

    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        if (webhook) {
            waitUntil(helper.cacheSet(privateKey, {hook:webhook}).catch((err) => {}));
        } else {
            waitUntil(helper.cacheDel(privateKey, 'hook').catch((err) => {}));
        }

        if (statsPresent) {
          reply.send(await helper.privateStats(privateKey));
        } else {
          const dataArray = await helper.privateConsume(privateKey);
          if (!dataArray.length) throw new Error('No Data');
          reply.send(dataArray);
        }
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
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        const cdnURL = await helper.githubPushJSON(privateKey, request.body);
        if (!cdnURL) throw new Error('Push to GitHub CDN failed');

        if (redirectOnOk == null) {
            reply.send({
              message: "Done",
              error: "Ok",
              statusCode: reply.statusCode,
              cdn: cdnURL
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
            } else if (err.message === 'No Payload') {
                callBadRequest(reply, 'No data provided in the request body');
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
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
          if (! await helper.githubPushJSON(privateKey, null, true)) throw new Error('Push to GitHub CDN failed');
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
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        const cdnURL = await helper.githubPushJSON(privateKey);
        if (!cdnURL) throw new Error('Push to GitHub CDN failed');

        reply.send({
          message: "Done",
          error: "Ok",
          statusCode: reply.statusCode,
          cdn: cdnURL
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

fastify.post('/private/:privateKey.kv', async (request, reply) => {
    const { privateKey } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    const fresh = 'new' in request.query;
    const password = request.query.password;
    const views = request.query.views;
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        await helper.kvSet(privateKey, request.body, { password, views, fresh });
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
            } else if (err.message === 'No Payload') {
                callBadRequest(reply, 'No data provided in the request body');
            } else if (err.message === 'Insufficient Storage') {
                callInsufficientStorage(reply, 'Delete existing key(s) before adding new one(s)');
            } else {
                callInternalServerError(reply, err.message);
            }
        } else {
            reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.get('/private/:privateKey.kv', async (request, reply) => {
    const { privateKey } = request.params;
    const viewsPresent = 'views' in request.query;

    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        if (viewsPresent) {
          reply.send(await helper.kvViews(privateKey));
        } else {
          reply.send(await helper.kvScan(privateKey));
        }
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

fastify.delete('/private/:privateKey.kv/:key?', async (request, reply) => {
    const { privateKey, key } = request.params;
    const keys = [];
    if (key) keys.push(key);
    const commaSeparatedKeys = request.query.keys;
    if (commaSeparatedKeys) keys.push(commaSeparatedKeys.split(','));
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        await helper.kvDelete(privateKey, ...keys);
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

fastify.patch('/private/:privateKey.kv', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');

        await helper.kvRefresh(privateKey);
        
        reply.send({
          message: "Done",
          error: "Ok",
          statusCode: reply.statusCode
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

fastify.get('/public/:publicKey.kv/:key?', async (request, reply) => {
    const { publicKey, key } = request.params;
    const password = request.query.password;
    const keys = [];
    if (key) keys.push(key);
    const commaSeparatedKeys = request.query.keys;
    if (commaSeparatedKeys) keys.push(...commaSeparatedKeys.split(','));
    try {
        if (await helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');
        reply.send(await helper.kvGet(publicKey, password, ...keys));
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

fastify.post('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
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
            } else if (err.message === 'No Payload') {
                callBadRequest(reply, 'No data provided in the request body');
            } else if (err.message === 'Already Exists') {
                callConflict(reply, 'Field already exists. GET publicly before POSTing new value');
            } else if (err.message === 'Insufficient Storage') {
                callInsufficientStorage(reply, 'GET existing field(s) before POSTing new one(s)');
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
        if (await helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');
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
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
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

fastify.all('/private/:privateKey.pipe', async (request, reply) => {
    const { privateKey } = request.params;
    const pipeFail = request.query.fail;
    try {
        if (await helper.parseKey(privateKey, { validate: false }).type !== 'private') throw new Error('Unauthorized');
        const pipeURL = await helper.pipeToPublic(privateKey, request.method);
        if (pipeFail) waitUntil(helper.cacheSet(privateKey, { pipeFail }));
        reply.redirect(pipeURL, 307);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'Method Not Allowed') {
            callMethodNotAllowed(reply, 'GET,POST,PUT', 'Provided method is not allowed for piping');
        } else {
            callInternalServerError(reply, err.message);
        }
    }
});

fastify.all('/public/:publicKey.pipe', async (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (await helper.parseKey(publicKey, { validate: false }).type !== 'public') throw new Error('Unauthorized');
        const pipeURL = await helper.pipeToPrivate(publicKey, request.method);
        if (pipeURL) {
            reply.redirect(pipeURL, 307);
        } else {
            const page404 = await helper.cacheGet(publicKey, 'pipeFail');
            if (page404) {
                reply.redirect(page404, 303);
            } else {
                throw new Error('No Data');
            }
        }
    } catch (err) {
        if (err.message == 'Unauthorized') {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            reply.callNotFound();
        } else if (err.message === 'Method Not Allowed') {
            callMethodNotAllowed(reply, 'GET,POST,PUT', 'Provided method is not allowed for piping');
        } else {
            callInternalServerError(reply, err.message);
        }
    }
});

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
