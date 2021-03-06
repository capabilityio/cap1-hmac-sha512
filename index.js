"use strict";

const crypto = require("crypto");
const _path = require("path");

const FIFTEEN_MINUTES_IN_MS = 1000 * 60 * 15;
const ALGORITHM = "CAP1-HMAC-SHA512";
const CAPABILITY_DATE_HEADER = "X-Cap-Date";
const CREDENTIAL_TERMINATION_STRING = "cap1_request";
const DEFAULT_CANONICAL_URI = "/";
const DEFAULT_HTTP_REQUEST_METHOD = "GET";

const base64urlEncodedHash = (str = "") => toUrlSafeBase64(crypto.createHash("sha512").update(str).digest("base64"));

const createCanonicalHeaders = headers =>
{
    const lowercaseHeaders =
        Object.keys(headers)
            .reduce(
                (lowercaseHeaders, header) =>
                {
                    lowercaseHeaders[header.toLowerCase()] = headers[header];
                    return lowercaseHeaders;
                },
                {}
            );
    return Object.keys(lowercaseHeaders)
            .sort()
            .map(header => `${header}:${trimall(lowercaseHeaders[header])}\n`)
            .join("");
};

const createCanonicalQueryString = queryString => (
    (queryString = queryString || "") &&
    queryString.split("&")
        .sort()
        .map(pair => pair.split("="))
        .map(pair => `${encodeURIComponent(decodeURIComponent(pair[0]))}=${encodeURIComponent(decodeURIComponent(pair[1]))}`)
        .join("&")
);

const createCredential = ({ keyId, credentialScope }) => `${keyId}/${credentialScope}`;

const createCredentialScope = ({ isoDateBasic, host }) => `${isoDateBasic.replace(/T.*/, "")}/${host.toLowerCase()}/${CREDENTIAL_TERMINATION_STRING}`;

const createIsoDateBasic = date => `${(date ? new Date(date) : new Date()).toISOString().replace(/-/g, '').replace(/:/g, '').replace(/\..*/, '')}Z`;

const createSignedHeaders = headers => (
    Object.keys(headers)
        .map(header => header.toLowerCase())
        .sort()
        .join(";")
);

const createStringToSign = ({ algorithm, isoDateBasic, credentialScope, canonicalRequest }) => (
    [
        algorithm,
        isoDateBasic,
        credentialScope,
        base64urlEncodedHash(canonicalRequest)
    ]
    .join("\n")
);

const hmac = (key, stringToSign, format) => crypto.createHmac("sha512", key).update(stringToSign).digest(format);

const hopByHopHeader =
{
    connection: true,
    "keep-alive": true,
    "proxy-authenticate": true,
    "proxy-authorization": true,
    te: true,
    trailer: true,
    "transfer-encoding": true,
    upgrade: true
};

const parseKeyId = authorization =>
{
    if (!authorization)
    {
        return false;
    }
    if (!authorization.startsWith(`${ALGORITHM} `))
    {
        return false;
    }
    let parts = authorization.slice(`${ALGORITHM} `.length).trim().split(",");
    if (parts.length != 3)
    {
        return false;
    }
    let credential = parts[0];
    if (!credential.startsWith("Credential="))
    {
        return false;
    }
    credential = credential.slice("Credential=".length);
    parts = credential.split("/");
    if (parts.length != 4)
    {
        return false;
    }
    return parts[0];
};

const parseSignedHeaders = authorization =>
{
    if (!authorization)
    {
        return [];
    }
    const match = authorization.match(/SignedHeaders=(.+),Signature/);
    if (!match)
    {
        return [];
    }
    let headers = match[1].split(";");
    return headers;
};

const toUrlSafeBase64 = base64 => base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const trimall = (string = "") => (
    ("" + string) // ensure type conversion to string
        .split(`"`)
        .reduce((state, part) =>
            {
                if (state.quoteToggle % 2)
                {
                    state.str += part.replace(/\s+/g, " ");
                }
                else
                {
                    state.str += `"${part}"`;
                }
                state.quoteToggle++;
                return state;
            },
            {
                quoteToggle: 1,
                str: ""
            }
        ).str.trim()
);

const sign = (
    {
        headers,
        httpRequestMethod = DEFAULT_HTTP_REQUEST_METHOD,
        key,
        keyId,
        path = DEFAULT_CANONICAL_URI,
        queryString = ""
    }
) =>
{
    // local copy of headers so we don't mutate ones in params
    let capDateHeaderValue, host;
    headers = Object.entries(headers)
        .map(([name, value]) =>
            {
                switch (name.toLowerCase())
                {
                    case "host":
                        host = value;
                        break;
                    case "x-cap-date":
                        const date = value;
                        capDateHeaderValue = `${date.slice(0,4)}-${date.slice(4,6)}-${date.slice(6,8)}T${date.slice(9,11)}:${date.slice(11,13)}:${date.slice(13,15)}Z`;
                        break;
                }
                return [name, value];
            }
        )
        .reduce((headers, [name, value]) =>
            {
                if (!hopByHopHeader[name.toLowerCase()])
                {
                    headers[name] = value;
                }
                return headers;
            },
            {}
        );

    if (!host)
    {
        throw new Error("Host header not found.");
    }

    // 1: Create canonical request

    const isoDateBasic = createIsoDateBasic(capDateHeaderValue);
    if (!capDateHeaderValue)
    {
        headers[CAPABILITY_DATE_HEADER] = isoDateBasic;
    }

    const canonicalHeaders = createCanonicalHeaders(headers);
    const signedHeaders = createSignedHeaders(headers);
    const credentialScope = createCredentialScope(
        {
            isoDateBasic,
            host
        }
    );
    const credential = createCredential(
        {
            keyId,
            credentialScope
        }
    );
    const canonicalQueryString = createCanonicalQueryString(queryString);
    const canonicalUri = encodeURIComponent(_path.normalize(decodeURIComponent(path)));
    const canonicalRequest =
    [
        httpRequestMethod.toUpperCase(),
        canonicalUri,
        canonicalQueryString,
        canonicalHeaders,
        signedHeaders
    ]
    .join("\n");

    // 2: Create string to sign

    const stringToSign = createStringToSign(
        {
            algorithm: ALGORITHM,
            isoDateBasic,
            credentialScope,
            canonicalRequest
        }
    );

    // 3: Derive signing key

    const kSecret = key;
    const kDate = hmac(`CAP1${kSecret}`, isoDateBasic.replace(/T.*/, ""), "binary");
    const kHost = hmac(kDate, host, "binary");
    const kSigning = hmac(kHost, CREDENTIAL_TERMINATION_STRING, "binary");

    // 4: Calculate the signature

    const signature = toUrlSafeBase64(hmac(kSigning, stringToSign, "base64"));

    const authorization = `${ALGORITHM} Credential=${credential},SignedHeaders=${signedHeaders},Signature=${signature}`;

    return (
        {
            algorithm: ALGORITHM,
            authorization,
            credential,
            "x-cap-date": isoDateBasic,
            signedHeaders,
            signature
        }
    );
};

const verify = (
    {
        headers,
        httpRequestMethod,
        path,
        queryString,
        secret,
        now = new Date()
    },
    callback
) =>
{
    if (!(secret instanceof Function))
    {
        throw new Error("secret is not a function");
    }

    let authorization, signedHeaders, capDateHeaderValue;
    // local copy of headers for signature
    headers = Object.entries(headers)
        .map(([name, value]) =>
            {
                switch (name.toLowerCase())
                {
                    case "authorization":
                        authorization = value;
                        signedHeaders = parseSignedHeaders(value)
                            .reduce((headers, header) =>
                                {
                                    headers[header] = true;
                                    return headers;
                                },
                                {}
                            );
                        break;
                    case "x-cap-date":
                        const date = value;
                        capDateHeaderValue = `${date.slice(0,4)}-${date.slice(4,6)}-${date.slice(6,8)}T${date.slice(9,11)}:${date.slice(11,13)}:${date.slice(13,15)}Z`;
                        break;
                }
                return [name, value];
            }
        )
        .reduce((headers, [name, value]) =>
            {
                if (signedHeaders[name.toLowerCase()])
                {
                    headers[name] = value;
                }
                return headers;
            },
            {}
        );

    if (!capDateHeaderValue)
    {
        return callback(undefined, false);
    }

    const timeDiff = Math.abs(now.getTime() - new Date(capDateHeaderValue).getTime());
    if (timeDiff > FIFTEEN_MINUTES_IN_MS)
    {
        return callback(undefined, false);
    }

    const keyId = parseKeyId(authorization);
    if (!keyId)
    {
        return callback(undefined, false);
    }

    secret(keyId, (error, key) =>
        {
            if (error || !key)
            {
                return callback(undefined, false);
            }
            const result = sign(
                {
                    headers,
                    httpRequestMethod,
                    key,
                    keyId,
                    path,
                    queryString
                }
            );
            return callback(undefined, result.authorization == authorization);
        }
    );
};

module.exports =
{
    ALGORITHM,
    sign,
    verify
};
