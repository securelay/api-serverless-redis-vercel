/*
Brief: Get ID of this endpoint
Run: node --env-file=.env id.js
*/

import { id } from './api/_utils.js';

console.log(await id());
