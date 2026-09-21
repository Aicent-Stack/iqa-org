// The same three lines as the README quickstart — runnable, so the example can
// be CHECKED rather than believed. Its expected output is the route fingerprint
// the published conformance vectors pin for that address.
//
//   node examples/quickstart.mjs
//   5c378581

import { parse } from '../src/iqa-uri.mjs';

const r = parse('iqa://3f9a1b2c.gateway.iqa');

console.log(r.subject);        // '3f9a1b2c'      (8-hex routing short form)
console.log(r.organ);          // 'gateway'       (closed set: forge|tss|gateway)
console.log(r.action);         // null            (omitted = standing read, SAFE)
console.log(r.route_hex);      // '5c378581'      <- pinned by the published vectors
