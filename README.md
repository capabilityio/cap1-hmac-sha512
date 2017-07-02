# cap1-hmac-sha512

_Stability: 1 - [Experimental](https://github.com/tristanls/stability-index#stability-1---experimental)_

[![NPM version](https://badge.fury.io/js/cap1-hmac-sha512.png)](http://npmjs.org/package/cap1-hmac-sha512)

## Contributors

[@tristanls](https://github.com/tristanls)

## Contents

  * [Overview](#overview)
  * [Installation](#installation)
  * [Tests](#tests)
  * [Usage](#usage)
  * [Documentation](#documentation)
  * [Releases](#releases)

## Overview

This module provides specification and reference implementation of Capability Signature Version 1 `CAP1-HMAC-SHA512`.

The signature is based on [AWS Signature Version 4](http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) with the following modifications:

* Algorithm used is `CAP1-HMAC-SHA512`.
* Credential termination string is `cap1_request` instead of `aws4_request`.
* `sha512` is used throughout instead of `sha256`.
* `X-Cap-Date` header is used instead of `X-Amz-Date` or `Date`.
* Request payload is not used as part of the signature.
* Credential scope uses `host` instead of `region` and `service`.
* Signing key derivation uses `host` instead of `region` and `service`.
* Generated string to sign uses `base64url` encoded `sha512` hash of canonical request instead of `hex` encoded `sha256` hash.
* Signature is `base64url` encoded instead of `hex`.

## Installation

    npm install cap1-hmac-sha512

## Usage

To run the below example run:

    npm run demo

```javascript
"use strict";

const cap1HmacSha512 = require("../index.js");
const http = require("http"); // not https for demo only
const url = require("url");

const secrets = // hardcoded for demo only
{
    "someId": "mySecret"
};

const server = http.createServer((req, resp) =>
    {
        console.log("request received:", req.headers);
        const parsedUrl = url.parse(req.url);
        const verifyParams =
        {
            headers: req.headers,
            httpRequestMethod: req.method,
            path: parsedUrl.pathname,
            queryString: parsedUrl.query,
            secret: (keyId, callback) => callback(undefined, secrets[keyId])
        };
        cap1HmacSha512.verify(verifyParams, (error, authorized) =>
            {
                console.log("request authorized:", authorized);
                if (authorized)
                {
                    resp.statusCode = 200;
                }
                else
                {
                    resp.statusCode = 401;
                }
                resp.end();
            }
        );
        req.on("data", () => {}); // drain request
    }
);

server.listen(8888, () =>
    {
        console.log("server listening");
        const options =
        {
            host: "localhost",
            headers:
            {
                host: "localhost:8888",
                connection: "close"
            },
            method: "GET",
            path: "/somewhere?page=12",
            port: 8888
        };
        const signature = cap1HmacSha512.sign(
            {
                headers: options.headers,
                httpRequestMethod: options.method,
                key: secrets["someId"],
                keyId: "someId",
                path: "/somewhere",
                queryString: "page=12"
            }
        );
        options.headers.authorization = signature.authorization;
        options.headers["x-cap-date"] = signature["x-cap-date"];
        console.log("client request:", options);
        http.request(options, resp =>
            {
                console.log("response status code:", resp.statusCode);
                resp.on("data", () => {}); // drain response
                delete options.headers["x-cap-date"];
                http.request(options, resp =>
                    {
                        console.log("response status code:", resp.statusCode);
                        resp.on("data", () => {}); // drain response
                        process.exit(0);
                    }
                ).end();
            }
        ).end();
    }
);

```

## Tests

    npm test

## Documentation

### Cap1HmacSha512

**Public API**
  * [sign(params)](#signparams)
  * [verify(params, callback)](#verifyparams-callback)

#### sign(params)

  * `params`: _Object_ Signature parameters.
    * `headers`: _Object_ HTTP request headers.
    * `httpRequestMethod`: _String_ _(Default: "GET")_ HTTP request method.
    * `key`: _String_ Secret to sign with corresponding to provided `keyId`.
    * `keyId`: _String_ Id of the secret to sign with.
    * `path`: _String_ _(Default: "/")_ HTTP request path.
    * `queryString`: _String_ _(Default: "")_ HTTP request query string.
  * Return: _Object_ Result.
    * `algorithm`: _String_ Algorithm used, `CAP1-HMAC-SHA512`.
    * `authorization`: _String_ HTTP Authorization header contents.
    * `credential`: _String_ Credential used for signing.
    * `x-cap-date`: _String_ HTTP X-Cap-Date header contents.
    * `signedHeaders`: _String_ List of headers used for signing.
    * `signature`: _String_ base64url encoded signature.

Calculates the `CAP1-HMAC-SHA512` signature given provided `params`. The `authorization` parameter from the result can be used directly as the `Authorization` header in HTTP request.

If `params.headers["X-Cap-Date"]` is not provided, an `X-Cap-Date` header will be generated and used as part of the signature. For the HTTP request to be valid, the `x-cap-date` field from the result must be used as the `X-Cap-Date` header in the HTTP request.

#### verify(params, callback)

  * `params`: _Object_ Verification parameters.
    * `headers`: _Object_ HTTP request headers.
    * `httpRequestMethod`: _String_ HTTP request method.
    * `path`: _String_ HTTP request path.
    * `queryString`: _String_ HTTP request query string.
    * `secret`: _Function_ `(keyId, callback) => {}` Function to retrieve `key` material corresponding to provided `keyId`.
      * `keyId`: _String_ Key id from `CAP1-HMAC-SHA512` signature to retrieve `key` material for.
      * `callback`: _Function_ `(error, key) => {}` Callback to call with error or key material.
  * `callback`: _Function_ `(error, authorized) => {}`
    * `error`: _Error_ Error, if any.
    * `authorized`: _Boolean_ `true` if signature is verified, `false` otherwise.

Extracts `keyId` from `Authorization` header, retrieves corresponding `key` material via `secret` callback, and calculates `CAP1-HMAC-SHA512` signature given provided `params`. If signature is verified, it calls callback with `authorized=true`, otherwise, callback is called with `authorized=false` or an `error`.

## Releases

[Current releases](https://github.com/capabilityio/cap1-hmac-sha512/releases).

### Policy

We follow the semantic versioning policy ([semver.org](http://semver.org/)) with a caveat:

> Given a version number MAJOR.MINOR.PATCH, increment the:
>
>MAJOR version when you make incompatible API changes,<br/>
>MINOR version when you add functionality in a backwards-compatible manner, and<br/>
>PATCH version when you make backwards-compatible bug fixes.

**caveat**: Major version zero is a special case indicating development version that may make incompatible API changes without incrementing MAJOR version.
