# libtrusttoken

libtrusttoken is a basic library to expose Trust Token functionality to issuers
as part of the Chrome Origin Trial. A non-production demo is shown in demo/.

Project links:

  * [General Updates](https://sites.google.com/a/chromium.org/dev/updates/trust-token)
  * [Trust Token API](https://github.com/wicg/trust-token-api)

This is not an officially supported Google product.

## Versions

Currently libtrusttoken supports two versions of the Trust Token API:

1. v2_allpublic - A variant that allows the use of 6 public metadata values.
1. v2_privatemetadata - A variant that allows the use of one bit of private metadata and 3 public metadata values.

Both versions of the Trust Token API are compatible with Chrome M88.

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
