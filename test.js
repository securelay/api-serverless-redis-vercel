/*
Brief: Testing
Run: node --env-file=.env test.js
*/

import * as helper from './api/_utils.js';

// process.exit(); // Use this to exit this script

const key = helper.genKeyPair();

console.log(JSON.stringify(key));

console.log('This should show public: ', helper.parseKey(key.public)['type']);
console.log('This should show private: ', helper.parseKey(key.private).type);
console.log('This should show true: ', helper.parseKey('random', {validate: false}).type === undefined );

console.log('Stream token private POST:', await helper.streamToken(key.private, false));
console.log('Stream token public GET:', await helper.streamToken(key.public));
console.log('Stream token public POST:', await helper.streamToken(key.public, false));
console.log('Stream token public POST:', await helper.streamToken(key.public, false));
console.log('Stream token private GET:', await helper.streamToken(key.private, true));

await helper.publicProduce(key.public, 'dataA hi"');
await helper.publicProduce(key.public, 'dataB hi"');
await helper.publicProduce(key.public, 'dataC hi"');

console.log(await helper.privateConsume(key.private));

await helper.privateProduce(key.private, 'data hi"');
console.log(await helper.publicConsume(key.public));

await helper.oneToOneProduce(key.private, 'some Key', 'data "for one to one at some key');
console.log(await helper.oneToOneConsume(key.public, 'some Key'));
console.log(await helper.oneToOneTTL(key.private, 'some Key'));

console.log('End of synchronous execution. Anything logged after this is from async only!')
