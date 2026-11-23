import test from 'node:test';
import assert from 'node:assert/strict';
import { validatePackageText, validateRsaJwk, parseJwkText } from '../js/tools/sshare.js';

const encode = value => Buffer.from(value).toString('base64url');
const APP_ID = 'Admin Toolbox Secure Password Share';

function validPasswordPackage() {
  return {
    format: 'admin-toolbox-secure-secret',
    version: 1,
    type: 'secret',
    alg: 'PBKDF2-SHA256/AES-256-GCM',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: 600000,
    salt: encode(Buffer.alloc(16)),
    iv: encode(Buffer.alloc(12)),
    aad: encode(`${APP_ID}|v1|password`),
    ciphertext: encode(Buffer.alloc(16))
  };
}

test('Secure Share accepts a bounded valid package', () => {
  const pkg = validPasswordPackage();
  assert.equal(validatePackageText(JSON.stringify(pkg)).iterations, 600000);
});

test('Secure Share rejects excessive PBKDF2 iterations and malformed parameters', () => {
  const excessive = validPasswordPackage();
  excessive.iterations = Number.MAX_SAFE_INTEGER;
  assert.throws(() => validatePackageText(JSON.stringify(excessive)), /iteration count/);

  const badSalt = validPasswordPackage();
  badSalt.salt = encode(Buffer.alloc(15));
  assert.throws(() => validatePackageText(JSON.stringify(badSalt)), /salt/);

  const badIv = validPasswordPackage();
  badIv.iv = encode(Buffer.alloc(16));
  assert.throws(() => validatePackageText(JSON.stringify(badIv)), /IV/);
});

test('Secure Share rejects oversized package text and malformed RSA JWKs', () => {
  assert.throws(() => validatePackageText(' '.repeat(2 * 1024 * 1024 + 1)), /2 MiB/);
  assert.throws(() => validateRsaJwk({ kty: 'RSA', n: encode(Buffer.alloc(256)), e: 'AQAB' }), /4096-bit/);
  assert.throws(() => validateRsaJwk({ kty: 'RSA', n: encode(Buffer.alloc(512, 0x80)), e: 'AQAB', d: 'private' }), /public JWK/);
});


test('Secure Share bounds imported JWK JSON and validates 4096-bit key components', () => {
  assert.throws(() => parseJwkText(' '.repeat(16 * 1024 + 1)), /16 KiB/);
  const publicJwk = { kty: 'RSA', n: encode(Buffer.concat([Buffer.from([0x80]), Buffer.alloc(511)])), e: 'AQAB' };
  assert.equal(parseJwkText(JSON.stringify(publicJwk)).kty, 'RSA');
  const privateJwk = {
    ...publicJwk,
    d: encode(Buffer.alloc(512)),
    p: encode(Buffer.alloc(256)),
    q: encode(Buffer.alloc(256)),
    dp: encode(Buffer.alloc(256)),
    dq: encode(Buffer.alloc(256)),
    qi: encode(Buffer.alloc(256))
  };
  assert.equal(parseJwkText(JSON.stringify(privateJwk), true).kty, 'RSA');
  privateJwk.dp = encode(Buffer.alloc(128));
  assert.throws(() => parseJwkText(JSON.stringify(privateJwk), true), /component lengths/);
});
