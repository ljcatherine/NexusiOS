'use strict';

const assert = require('node:assert/strict');
const forge = require('node-forge');

assert.equal(require('node-forge/package.json').version, '1.4.1');
const {BigInteger} = forge.jsbn;
const publicKey = forge.pki.setRsaPublicKey(
  new BigInteger('f'.repeat(256), 16),
  new BigInteger('1', 10)
);
const digestHex = '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9';
const prefix = `0001${'ff'.repeat(72)}00`;
const suffix = `0420${digestHex}`;
const vectors = [
  ['NULL parameters with content', `${prefix}3033300f06096086480165030402010502beef${suffix}`],
  ['non-minimal long-form sequence lengths', `${prefix}30813230810d060960864801650304020105000420${digestHex}`],
  ['unrecognized ASN.1 parameters element', `${prefix}3033300f06096086480165030402010202beef${suffix}`],
];

for (const [name, digestInfo, paddingBytes] of [
  ['canonical NULL parameters', `3031300d060960864801650304020105000420${digestHex}`, 74],
  ['canonical omitted parameters', `302f300b06096086480165030402010420${digestHex}`, 76],
]) {
  const messageDigest = forge.md.sha256.create();
  messageDigest.update('hello world!');
  const signature = `0001${'ff'.repeat(paddingBytes)}00${digestInfo}`;
  assert.equal(
    publicKey.verify(messageDigest.digest().getBytes(), Buffer.from(signature, 'hex').toString('binary')),
    true,
    `${name} was incorrectly rejected`
  );
}

for (const [name, signatureHex] of vectors) {
  const messageDigest = forge.md.sha256.create();
  messageDigest.update('hello world!');
  const signature = Buffer.from(signatureHex, 'hex').toString('binary');
  assert.throws(
    () => publicKey.verify(messageDigest.digest().getBytes(), signature),
    /valid RSASSA-PKCS1-v1_5 DigestInfo value/,
    `${name} was not rejected`
  );
}

console.log('node-forge 1.4.1 accepts both canonical DigestInfo forms and rejects all three non-canonical regression vectors.');
