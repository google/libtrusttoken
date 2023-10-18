# libtrusttoken

libtrusttoken is a basic library to expose Private State Token functionality to issuers
as part of the Chrome Origin Trial. A non-production demo is shown in demo/.

Project links:

  * [General Updates](https://sites.google.com/a/chromium.org/dev/updates/trust-token)
  * [Private State Token API](https://github.com/wicg/trust-token-api)
  * [Design/Implementation Considerations for Issuers](/ISSUERS.md)
This is not an officially supported Google product.

## Versions

Currently libtrusttoken supports one version of the Private State Token API:

1. v2_allpublic - A variant that allows the use of 6 public metadata values.

## Building

Using Ninja (note the 'N' is capitalized in the cmake invocation):

    mkdir build
    cd build
    cmake -GNinja ..
    ninja

Using Make (does not work on Windows):

    mkdir build
    cd build
    cmake ..
    make

## General API

To use this API, the caller should construct a `PrivateStateTokenIssuer` with the appropriate configuration (Currently the issuer version and the max batchsize that is supported).

The object should then be initialized with the keys that this issuer supports using `AddKey` (these keys are generated using `GenerateKey`). The number of keys allowed is based on the version of the protocol being used (6 keys for the `v2_allpublic` and 3 keys for `v2_privatemetadata`).

`GetCommitment` can be used to construct a JSON dictionary that acts as a suitable key commitment for the Private State Token protocol. The `commitment_id` should be an monotonically increasing ID as keys are rotated out and new commitments are generated. The resulting JSON dictionary should be served at some public endpoint and is part of the Issuer registration process for various UAs (browsers).

On receiving a Private State Token issuance request, the issuer should extract the `Sec-Private-State-Token` header and pass it into `Issue`, along with the metadata values that should be encoded in the tokens and the maximum number of tokens to issue. The resulting string should be included in the `Sec-Private-State-Token` header response.

On receiving a Private State Token redemption request, the issuer should extract the `Sec-Private-State-Token` header and pass it into `Redeem`. The outputs should be used to construct a redemption response which should be included in the `Sec-Private-State-Token` header. The Private State Token API describes one potential redemption record format.
