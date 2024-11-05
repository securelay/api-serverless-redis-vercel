/*
Brief: Testing
Run: node --env-file=.env test.js
*/

import * as helper from './helper.js';


const key = helper.genKeyPair();

console.log(JSON.stringify(key));

console.log('This should show public: ' + helper.validate(key.public));
console.log('This should show private: ' + helper.validate(key.private));
console.log('This should show false: ' + helper.validate('random'));

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
