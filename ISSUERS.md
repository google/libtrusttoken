# Trust Token Issuer Considerations

There are a number of considerations that an issuer must make when becoming a Trust Token issuer.

## Issuance Strategy
Different issuers will use different information, such as the challenge
response sent in the issuance request (in the case of CAPTCHA style issuers)
or the first-party state available in the issuance request, to issue tokens.

Using that information can provide the issuer some idea of whether tokens
should be issued (and what particular metadata should be included in the
token).

### Issuance Replay Protection
One thing that issuers should consider is that if a client can replay the
same issuance request to get an unlimited number of tokens, then it
becomes very easy for a malicious client to get a ton of tokens and then
distribute them to a botnet or other compromised clients.

Therefore, issuers should ensure that either a new challenge is required
for each token issuance or that if using first-party state, the number
of tokens previously issued is taken into account before issuing new
tokens.

## Redemption Replay Protection
In order to prevent malicious clients from replaying the same Trust Token
multiple times, the issuer should keep track of the tokens it has received
(via the `out_token` field of the `Redeem` method) and return an error on
attempts to redeem duplicate tokens.

While this is fairly straightforward in scenarios where a single token is
performing the redemption, in distributed settings where the issuer may be
operating in multiple data centers, the issuer may need to make the tradeoff
between latency for the redemption request or doing localized replay protection
until the various datacenters propogate the tokens they've seen globally.

## Redemption Record Format
One key consideration is how issuers propogate the value of a redeemed token
to other parties that may want to consume a redemption record. One approach
is to create a redemption record containing the client data and the metadata
values which is signed by a key that can be verified by downstream consumers.
This allows downstream consumers of the redemption record to verify the
integrity of the record without needing to contact the issuer.

Including the client data in the redemption record allows an issuer to bind
a particular redemption to the context the redemption occurred in, preventing
a malicious client from pretending that the redemption happened at a different
time or different website.

The [Trust Token API](https://github.com/wicg/trust-token-api) explainer includes
one potential structure for the Redemption Record. Though depending on the data
included in the Redemption Record, the issuer may want to base64 encode it to
ensure it is transported in the `Sec-Trust-Token` header correctly.