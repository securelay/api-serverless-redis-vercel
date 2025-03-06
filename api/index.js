// Ref: https://fastify.dev/docs/latest/Reference/Routes/#async-await

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
    reply.code(401);
    return {message: msg, error: "Unauthorized", statusCode: reply.statusCode};
}

const callForbidden = function(reply, msg){
    reply.code(403);
    return {message: msg, error: "Forbidden", statusCode: reply.statusCode};
}

const callBadRequest = function(reply, msg){
    reply.code(400);
    return {message: msg, error: "Bad Request", statusCode: reply.statusCode};
}

const callInternalServerError = function(reply, msg){
    reply.code(500);
    return {message: msg, error: "Internal Server Error", statusCode: reply.statusCode};
}

const callConflict = function(reply, msg){
    reply.code(409);
    return {message: msg, error: "Conflict", statusCode: reply.statusCode};
}

const callInsufficientStorage = function(reply, msg){
    reply.code(507);
    return {message: msg, error: "Insufficient Storage", statusCode: reply.statusCode};
}

const callMethodNotAllowed = function(reply, allowedMethods, msg){
    reply.code(405).header('Allow', allowedMethods);
    return {message: msg, error: "Method Not Allowed", statusCode: reply.statusCode};
}

fastify.get('/keys', async (request, reply) => {
    return helper.genKeyPair();
})

fastify.get('/keys/:key', async (request, reply) => {
    const { key } = request.params;
    try {
      const publicKey = await helper.genPublicKey(key); // Also validates, even if key is public!
      const type = await helper.parseKey(key, { validate: false, part: "type" });
      return { type: type, public: publicKey };
    } catch (err) {
      if (err.message === 'Invalid Key') {
        return callBadRequest(reply, 'Provided key is invalid');
      } else {
        return callInternalServerError(reply, err.message);
      }
    }
})

fastify.post('/public/:publicKey/:channel?', async (request, reply) => {
    const { publicKey, channel } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    let payload = request.body;
    try {
        if (await helper.parseKey(publicKey, { validate: false, part: "type" }) !== 'public') throw new Error('Unauthorized');

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
            return {message: "Done", error: "Ok", statusCode: reply.statusCode, webhook: data.webhook};
        } else {
            return reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                return callUnauthorized(reply, 'Provided key is not Public');
            } else if (err.message === 'Invalid Key') {
                return callBadRequest(reply, 'Provided key is invalid');
            } else if (err.message === 'No Payload') {
                return callBadRequest(reply, 'No data provided in the request body');
            } else {
                return callInternalServerError(reply, err.message);
            }
        } else {
            return reply.redirect(redirectOnErr, 303);
        }
    }
})

fastify.get('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const webhook = request.query.hook;
    const statsPresent = 'stats' in request.query;

    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');

        if (webhook) {
            waitUntil(helper.cacheSet(privateKey, {hook:webhook}).catch((err) => {}));
        } else {
            waitUntil(helper.cacheDel(privateKey, 'hook').catch((err) => {}));
        }

        if (statsPresent) {
          return helper.privateStats(privateKey);
        } else {
          const dataArray = await helper.privateConsume(privateKey);
          if (!dataArray.length) throw new Error('No Data');
          return dataArray;
        }
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            return reply.callNotFound();
        } else {
            return callInternalServerError(reply, err.message);
        }
    }    
})

fastify.post('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');

        const cdnURL = await helper.githubPushJSON(privateKey, request.body);
        if (!cdnURL) throw new Error('Push to GitHub CDN failed');

        if (redirectOnOk == null) {
            return {
              message: "Published",
              error: "Ok",
              statusCode: reply.statusCode,
              cdn: cdnURL
            };
        } else {
            return reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                return callUnauthorized(reply, 'Provided key is not Private');
            } else if (err.message === 'Invalid Key') {
                return callBadRequest(reply, 'Provided key is invalid');
            } else if (err.message === 'No Payload') {
                return callBadRequest(reply, 'No data provided in the request body');
            } else {
                return callInternalServerError(reply, err.message);
            }
        } else {
            return reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.delete('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        const cdnURL = await helper.githubPushJSON(privateKey, null, true);
        if (!cdnURL) throw new Error('Push to GitHub CDN failed');
        reply.code(204);
        return {
          message: "Deleted",
          error: "Ok",
          statusCode: reply.statusCode,
          cdn: cdnURL
        };
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else {
            return callInternalServerError(reply, err.message);
        }
    }
})

fastify.patch('/private/:privateKey', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');

        const cdnURL = await helper.githubPushJSON(privateKey);
        if (!cdnURL) throw new Error('Push to GitHub CDN failed');

        return {
          message: "Renewed",
          error: "Ok",
          statusCode: reply.statusCode,
          cdn: cdnURL
        };
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else {
            return callInternalServerError(reply, err.message);
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
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        await helper.kvSet(privateKey, request.body, { password, views, fresh });
        if (redirectOnOk == null) {
            return {message: "Done", error: "Ok", statusCode: reply.statusCode};
        } else {
            return reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                return callUnauthorized(reply, 'Provided key is not Private');
            } else if (err.message === 'Invalid Key') {
                return callBadRequest(reply, 'Provided key is invalid');
            } else if (err.message === 'No Payload') {
                return callBadRequest(reply, 'No data provided in the request body');
            } else if (err.message === 'Insufficient Storage') {
                return callInsufficientStorage(reply, 'Delete existing key(s) before adding new one(s)');
            } else {
                return callInternalServerError(reply, err.message);
            }
        } else {
            return reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.get('/private/:privateKey.kv', async (request, reply) => {
    const { privateKey } = request.params;
    const viewsPresent = 'views' in request.query;

    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');

        if (viewsPresent) {
          return helper.kvViews(privateKey);
        } else {
          return helper.kvScan(privateKey);
        }
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            return reply.callNotFound();
        } else {
            return callInternalServerError(reply, err.message);
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
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        await helper.kvDelete(privateKey, ...keys);
        reply.code(204);
        return '';
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else {
            return callInternalServerError(reply, err.message);
        }
    }
})

fastify.patch('/private/:privateKey.kv', async (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');

        await helper.kvRefresh(privateKey);
        
        return {
          message: "Done",
          error: "Ok",
          statusCode: reply.statusCode
        };
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else {
            return callInternalServerError(reply, err.message);
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
        if (await helper.parseKey(publicKey, { validate: false, part: "type" }) !== 'public') throw new Error('Unauthorized');
        return helper.kvGet(publicKey, password, ...keys);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Public');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            return reply.callNotFound();
        } else {
            return callInternalServerError(reply, err.message);
        }
    }    
})

fastify.post('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    const redirectOnOk = request.query.ok;
    const redirectOnErr = request.query.err;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        await helper.oneToOneProduce(privateKey, key, JSON.stringify(helper.decoratePayload(request.body)));
        if (redirectOnOk == null) {
            return {message: "Done", error: "Ok", statusCode: reply.statusCode};
        } else {
            return reply.redirect(redirectOnOk, 303);
        }
    } catch (err) {
        if (redirectOnErr == null) {
            if (err.message == 'Unauthorized') {
                return callUnauthorized(reply, 'Provided key is not Private');
            } else if (err.message === 'Invalid Key') {
                return callBadRequest(reply, 'Provided key is invalid');
            } else if (err.message === 'No Payload') {
                return callBadRequest(reply, 'No data provided in the request body');
            } else if (err.message === 'Already Exists') {
                return callConflict(reply, 'Field already exists. GET publicly before POSTing new value');
            } else if (err.message === 'Insufficient Storage') {
                return callInsufficientStorage(reply, 'GET existing field(s) before POSTing new one(s)');
            } else {
                return callInternalServerError(reply, err.message);
            }
        } else {
            return reply.redirect(redirectOnErr, 303);
        }
    }    
})

fastify.get('/public/:publicKey/:key', async (request, reply) => {
    const { publicKey, key } = request.params;
    try {
        if (await helper.parseKey(publicKey, { validate: false, part: "type" }) !== 'public') throw new Error('Unauthorized');
        const data = await helper.oneToOneConsume(publicKey, key);
        if (!data) throw new Error('No Data');
        return data;
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Public');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else if (err.message === 'No Data') {
            return reply.callNotFound();
        } else {
            return callInternalServerError(reply, err.message);
        }
    }    
})

fastify.get('/private/:privateKey/:key', async (request, reply) => {
    const { privateKey, key } = request.params;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        return helper.oneToOneTTL(privateKey, key);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return callUnauthorized(reply, 'Provided key is not Private');
        } else if (err.message === 'Invalid Key') {
            return callBadRequest(reply, 'Provided key is invalid');
        } else {
            return callInternalServerError(reply, err.message);
        }
    }    
})

// Respond directly from an onRequest hook so that request.body need not be parsed!
// So, handler is a no-op.
fastify.all('/private/:privateKey.pipe', {
    onRequest: async (request, reply) => {
    const { privateKey } = request.params;
    const pipeFail = request.query.fail;
    try {
        if (await helper.parseKey(privateKey, { validate: false, part: "type" }) !== 'private') throw new Error('Unauthorized');
        const pipeURL = await helper.pipeToPublic(privateKey, request.method);
        if (pipeFail) waitUntil(helper.cacheSet(privateKey, { pipeFail }));
        return reply.redirect(pipeURL, 307);
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return reply.send(callUnauthorized(reply, 'Provided key is not Private'));
        } else if (err.message === 'Invalid Key') {
            return reply.send(callBadRequest(reply, 'Provided key is invalid'));
        } else if (err.message === 'Method Not Allowed') {
            return reply.send(callMethodNotAllowed(reply, 'GET,POST,PUT', 'Provided method is not allowed for piping'));
        } else {
            return reply.send(callInternalServerError(reply, err.message));
        }
    }
    }
  },
  () => {} // No-op handler
);

// Respond directly from an onRequest hook so that request.body need not be parsed!
// So, handler is a no-op.
fastify.all('/public/:publicKey.pipe', {
    onRequest: async (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (await helper.parseKey(publicKey, { validate: false, part: "type" }) !== 'public') throw new Error('Unauthorized');
        const pipeURL = await helper.pipeToPrivate(publicKey, request.method);
        if (pipeURL) {
            return reply.redirect(pipeURL, 307);
        } else {
            const page404 = await helper.cacheGet(publicKey, 'pipeFail');
            if (page404) {
                return reply.redirect(page404, 303);
            } else {
                throw new Error('No Data');
            }
        }
    } catch (err) {
        if (err.message == 'Unauthorized') {
            return reply.send(callUnauthorized(reply, 'Provided key is not Private'));
        } else if (err.message === 'Invalid Key') {
            return reply.send(callBadRequest(reply, 'Provided key is invalid'));
        } else if (err.message === 'No Data') {
            return reply.callNotFound();
        } else if (err.message === 'Method Not Allowed') {
            return reply.send(callMethodNotAllowed(reply, 'GET,POST,PUT', 'Provided method is not allowed for piping'));
        } else {
            return reply.send(callInternalServerError(reply, err.message));
        }
    }
    }
  },
  () => {} // No-op handler
);

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
