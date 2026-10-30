// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function issueCredential(key, subject) {
  return Q.issue({ key, scheme: 'national', credentialNo: 'ID 2026 0001', subject: Q.keyId(subject), level: 'high', validUntil: '2036-01-01T00:00:00.000Z', issuerLabel: 'National Identity Authority' });
}

test('an issued credential is a well formed signed record of the issuer', () => {
  const issuer = freshKey();
  const holder = freshKey();
  const cred = issueCredential(issuer, holder);
  assert.strictEqual(cred.format, 'qid/1');
  assert.strictEqual(cred.type, 'issue');
  assert.strictEqual(cred.algorithm, 'ML-DSA-65');
  assert.strictEqual(cred.signer.id, Q.keyId(issuer));
  assert.strictEqual(cred.statement.issuerKeyId, Q.keyId(issuer));
  assert.strictEqual(cred.statement.subjectKeyId, Q.keyId(holder));
  assert.match(cred.statement.credId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(cred.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(cred.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('renew is signed by the issuer and present is signed by the holder, both on the same credential', () => {
  const issuer = freshKey();
  const holder = freshKey();
  const cred = issueCredential(issuer, holder);
  const renewed = Q.renew({ key: issuer, credential: cred, validUntil: '2040-01-01T00:00:00.000Z' });
  const shown = Q.present({ key: holder, record: cred, purpose: 'boarding', audience: 'Airport Security' });
  assert.strictEqual(renewed.statement.credId, cred.statement.credId);
  assert.strictEqual(renewed.statement.issueRef, Q.recordRef(cred));
  assert.strictEqual(renewed.signer.id, Q.keyId(issuer));
  assert.strictEqual(shown.statement.credId, cred.statement.credId);
  assert.strictEqual(shown.statement.priorRef, Q.recordRef(cred));
  assert.strictEqual(shown.signer.id, Q.keyId(holder));
  assert.strictEqual(shown.statement.subjectKeyId, Q.keyId(holder));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const holder = freshKey();
  const base = { key, scheme: 'national', credentialNo: 'C1', subject: Q.keyId(holder), level: 'high', validUntil: '2036-01-01T00:00:00.000Z' };
  assert.throws(() => Q.issue(Object.assign({}, base, { scheme: 'wizard' })), /scheme must be one of/);
  assert.throws(() => Q.issue(Object.assign({}, base, { level: 'ultra' })), /level must be one of/);
  assert.throws(() => Q.issue(Object.assign({}, base, { credentialNo: '' })), /credentialNo is 1 to/);
  assert.throws(() => Q.issue(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.issue(Object.assign({}, base, { validUntil: 'forever' })), /validUntil must be an ISO/);
  assert.throws(() => Q.issue(Object.assign({}, base, { unknownField: 1 })), /is not an option of issue/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const holder = freshKey();
  assert.throws(() => issueCredential(new Uint8Array(16), holder), /32 byte Uint8Array seed/);
  assert.throws(() => issueCredential(new Uint8Array(32), holder), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const issuer = freshKey();
  const holder = freshKey();
  const cred = issueCredential(issuer, holder);
  const ok = await Q.verify(cred, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'issue');
  assert.strictEqual(ok.credId, cred.statement.credId);
  const wrongType = await Q.verify(cred, { type: 'present', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(cred, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const issuer = freshKey();
  const holder = freshKey();
  const cred = issueCredential(issuer, holder);
  const forged = JSON.parse(JSON.stringify(cred));
  forged.statement.level = 'basic';
  const r = await Q.verify(forged, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a presentation to the credential it refers to', async () => {
  const issuer = freshKey();
  const holder = freshKey();
  const cred = issueCredential(issuer, holder);
  const shown = Q.present({ key: holder, record: cred, purpose: 'boarding', audience: 'Airport Security' });
  const good = await Q.verify(shown, { type: 'present', network: 'testnet', requireAnchor: false, strict: false, prior: cred });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherCred = issueCredential(issuer, holder);
  const bad = await Q.verify(shown, { type: 'present', network: 'testnet', requireAnchor: false, strict: false, prior: otherCred });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'ID 2026 0001');
  const b = Q.subjectRef(secret, 'ID 2026 0001');
  const c = Q.subjectRef(secret, 'ID 2026 0002');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the identity line', () => {
  assert.strictEqual(Q.KIND, 1501);
  assert.strictEqual(Q.FORMAT, 'qid/1');
  assert.deepStrictEqual([...Q.TYPES], ['issue', 'renew', 'present', 'suspend', 'revoke']);
  assert.deepStrictEqual([...Q.SCHEMES], ['national', 'residence', 'driver', 'employee', 'student', 'health']);
  assert.deepStrictEqual([...Q.LEVELS], ['basic', 'substantial', 'high']);
});
