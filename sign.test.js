"use strict";

const clone = require("clone");

const cap1HmacSha512 = require("./index.js");

const VALID_PARAMS =
{
    headers:
    {
        Host: "foo.com"
    },
    key: "secret",
    keyId: "secretId"
};

it("does not mutate params", () =>
    {
        const params = clone(VALID_PARAMS);
        Object.freeze(params);
        Object.freeze(params.headers);
        Object.freeze(params.key);
        Object.freeze(params.keyId);
        Object.freeze(params.queryString);
        Object.freeze(params.path);
        Object.freeze(params.httpRequestMethod);
        expect(() => cap1HmacSha512.sign(params)).not.toThrow();
    }
);

it("throws if cannot find Host header", () =>
    {
        expect(() => cap1HmacSha512.sign(
            {
                headers:
                {
                    NoHost: "header"
                },
                key: "secret",
                keyId: "secretId"
            }
        )).toThrow(new Error("Host header not found."));
    }
);

it("does not throw if params.queryString is null", () =>
    {
        const params = clone(VALID_PARAMS);
        params.queryString = null;
        expect(() => cap1HmacSha512.sign(params)).not.toThrow();
    }
);

describe("result", () =>
{
    it("includes algorithm", () =>
        {
            expect(cap1HmacSha512.sign(VALID_PARAMS).algorithm).toBe("CAP1-HMAC-SHA512");
            expect(cap1HmacSha512.sign(VALID_PARAMS).algorithm).toBe(cap1HmacSha512.ALGORITHM);
        }
    );

    it("includes x-cap-date if no x-cap-date header provided", () =>
        {
            const params = clone(VALID_PARAMS);
            Object.keys(params.headers).map(header =>
                {
                    if (header.toLowerCase() == "x-cap-date")
                    {
                        delete params.headers[header];
                    }
                }
            );
            const result = cap1HmacSha512.sign(params);
            expect(result["x-cap-date"]).toBeTruthy();
            expect(result.signedHeaders.includes("x-cap-date")).toBeTruthy();
        }
    );

    it("includes provided x-cap-date", () =>
        {
            const params = clone(VALID_PARAMS);
            params.headers["x-cap-date"] = "20170701T221547Z";
            const result = cap1HmacSha512.sign(params);
            expect(result["x-cap-date"]).toBe("20170701T221547Z");
            expect(result.signedHeaders.includes("x-cap-date")).toBeTruthy();
        }
    );
});

describe("cap1HmacSha512.signature", () =>
{
    it(`uses "/" as default path`, () =>
        {
            const params = clone(VALID_PARAMS);
            params.headers["x-cap-date"] = "20170701T221547Z";
            const params2 = clone(params);
            params2.path = "/";
            expect(cap1HmacSha512.sign(params)).toEqual(cap1HmacSha512.sign(params2));
        }
    );

    it(`uses "GET" as default httpRequestMethod`, () =>
        {
            const params = clone(VALID_PARAMS);
            params.headers["x-cap-date"] = "20170701T221547Z";
            const params2 = clone(params);
            params2.httpRequestMethod = "GET";
            expect(cap1HmacSha512.sign(params)).toEqual(cap1HmacSha512.sign(params2));
        }
    );

    it(`uses "" as default queryString`, () =>
        {
            const params = clone(VALID_PARAMS);
            params.headers["x-cap-date"] = "20170701T221547Z";
            const params2 = clone(params);
            params2.queryString = "";
            expect(cap1HmacSha512.sign(params)).toEqual(cap1HmacSha512.sign(params2));
        }
    );

    it(`does not sign hop-by-hop headers`, () =>
        {
            const params = clone(VALID_PARAMS);
            params.headers["x-cap-date"] = "20170701T221547Z";
            const params2 = clone(params);
            [
                "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
                "TE", "Trailer", "Transfer-Encoding", "Upgrade"
            ]
            .map(hbhHeader =>
                {
                    params2.headers[hbhHeader] = "something";
                }
            );
            expect(cap1HmacSha512.sign(params)).toEqual(cap1HmacSha512.sign(params2));
        }
    );
});
