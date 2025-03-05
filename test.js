/*
Brief: Testing
Run: node --env-file=.env test.js
*/

import * as helper from './api/_utils.js';

// process.exit(); // Use this to exit this script

const key = await helper.genKeyPair();

console.log('Generate keypair:');
console.log(JSON.stringify(key));

console.log('\nParsing key type:')
console.log('Assert public:', await helper.parseKey(key.public).then(obj => obj['type']));
console.log('Assert private:', await helper.parseKey(key.private).then(({type}) => type));
console.log('Assert true:',
  await helper.parseKey('random', {validate: false}).then(obj => obj.type) === undefined
);

console.log('\nCache: set and get ...')
await helper.cacheSet(key.private, {fieldA: 'valA', fieldB: 'valB'});
console.log('Cache multiple values:', JSON.stringify(await helper.cacheGet(key.public, 'fieldA', 'fieldB', 'fieldC')));
console.log('Cache single value:', await helper.cacheGet(key.public, 'fieldB'));

console.log('\nPiping: tokens for private and public must match for complementary modes ...')
console.log('private POST:', await helper.pipeToPublic(key.private, 'POST'));
console.log('public GET:', await helper.pipeToPrivate(key.public, 'GET'));
console.log('public POST:', await helper.pipeToPublic(key.private, 'GET'));
console.log('public POST:', await helper.pipeToPublic(key.private, 'GET'));
console.log('public POST:', await helper.pipeToPrivate(key.public, 'POST'));

console.log('\nMessage queue: multiple public POSTs received with single private GET ...')
await helper.publicProduce(key.public, 'dataA');
await helper.publicProduce(key.public, 'dataB');
await helper.publicProduce(key.public, 'dataC');
console.log('private GET:', await helper.privateConsume(key.private));

console.log('\nKV: privately set and publicly get key-value pairs ...');
await helper.kvSet(key.private, {key: "value"});
console.log(JSON.stringify(await helper.kvGet(key.public, null, 'key', 'dummy')));

console.log('\nChannel: privately POST messages for one-time public consumption ...')
await helper.oneToOneProduce(key.private, 'channel', 'data for one-to-one relay at channel');
console.log('private GET:', await helper.oneToOneTTL(key.private, 'channel'));
console.log('public GET:', await helper.oneToOneConsume(key.public, 'channel'));

console.log('\nEnd of synchronous execution. Anything logged after this generated from async!')
