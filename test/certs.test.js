import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePem, renderAsn1 } from '../js/tools/certs.js';

const derSample = () => {
  const value = new TextEncoder().encode('example.test');
  return new Uint8Array([0x30, value.length + 2, 0x0c, value.length, ...value]);
};

test('certificate inspector accepts raw DER ASN.1 bytes', () => {
  const html = renderAsn1(derSample(), 'DER file');
  assert.match(html, /DER file/);
  assert.match(html, /example\.test/);
});

test('certificate inspector accepts PEM-wrapped DER bytes', () => {
  const der = derSample();
  const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64')}\n-----END CERTIFICATE-----`;
  assert.match(parsePem(pem), /example\.test/);
});

test('certificate inspector rejects malformed DER lengths', () => {
  assert.throws(() => renderAsn1(new Uint8Array([0x30, 0x20, 0x0c, 0x01, 0x41]), 'DER file'), /length/);
});
