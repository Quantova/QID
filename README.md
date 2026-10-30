# QID

QID is a live production post quantum identity credential tool for identity issuers, airports and verifiers on the Quantova network. It proves the issue, renewal, presentation, suspension and revocation of an identity credential, and it lets any third party confirm that history without trusting the party that created it.

QID proves records without disclosing them. Names, document numbers and every other personal detail stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A holder is named only by a chain address, never by their identity.

## What it records

Each record is a signed envelope of one of five types.

1. issue, an issuer states the scheme, credential number, holder, assurance level and expiry of a credential.
2. renew, the issuer extends the expiry of the credential.
3. present, the holder signs a presentation of the credential to a named audience for a stated purpose.
4. suspend, the issuer suspends the credential and states why.
5. revoke, the issuer revokes the credential and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, the issuer or the holder, and each later record links to the one before it so the whole life of a credential forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qid
```

## Use

```js
const qid = require('@quantovainc/qid');

const issuer = qid.generateKey();
const holder = qid.generateKey();
const credential = qid.issue({
  key: issuer,
  scheme: 'national',
  credentialNo: 'ID 2026 0001',
  subject: qid.keyId(holder),
  level: 'high',
  validUntil: '2036-01-01T00:00:00.000Z',
  issuerLabel: 'National Identity Authority',
});

const presentation = qid.present({ key: holder, record: credential, purpose: 'boarding', audience: 'Airport Security' });
const anchored = await qid.anchor(credential, { seed, index: 0, network: 'testnet' });
const result = await qid.verify(anchored[0], { type: 'issue', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The holder and the issuer are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
