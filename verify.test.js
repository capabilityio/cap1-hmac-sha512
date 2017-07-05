"use strict";

const clone = require("clone");

const cap1HmacSha512 = require("./index.js");

const SECRETS =
{
    "someId": "mySecret"
};

const VALID_PARAMS =
{
    headers:
    {
        host: "localhost:8888",
        connection: "close",
        authorization: "CAP1-HMAC-SHA512 Credential=someId/20170702/localhost:8888/cap1_request,SignedHeaders=connection;host;x-cap-date,Signature=lEV0szOupNaXRoZPsGYziaF-liIIwA0lIyCHJCK9AxYD7fXaSAlEABgKhZOA4cw2polyV0HujGiZVU6TdQcGAQ",
        "x-cap-date": "20170702T204657Z"
    },
    httpRequestMethod: "GET",
    now: new Date("2017-07-02T20:46:57Z"),
    path: "/somewhere",
    queryString: "page=12",
    secret: (keyId, callback) => callback(undefined, SECRETS[keyId])
};

it("does not mutate params", () =>
    {
        const params = clone(VALID_PARAMS);
        Object.freeze(params);
        Object.keys(params).map(key =>
            {
                Object.freeze(params[key]);
            }
        );
        expect(() => cap1HmacSha512.verify(params, () => {})).not.toThrow();
    }
);

it("throws if secret is not a function", () =>
    {
        const params = clone(VALID_PARAMS);
        params.secret = { someId: "secret" };
        expect(() => cap1HmacSha512.verify(params, () => {}))
            .toThrow(new Error("secret is not a function"));
    }
);

describe("result", () =>
{
    describe("is false if", () =>
    {
        it("request is missing X-Cap-Date header", done =>
            {
                const params = clone(VALID_PARAMS);
                delete params.headers["x-cap-date"];
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done();
                    }
                );
            }
        );
        it("request Authorization header does not have valid keyId", done =>
            {
                const params = clone(VALID_PARAMS);
                params.headers.authorization = "CAP1-HMAC-SHA512 Credential=/20170702/localhost:8888/cap1_request,SignedHeaders=connection;host;x-cap-date,Signature=lEV0szOupNaXRoZPsGYziaF-liIIwA0lIyCHJCK9AxYD7fXaSAlEABgKhZOA4cw2polyV0HujGiZVU6TdQcGAQ";
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done();
                    }
                );
            }
        );
        it("request Authorization header does not match calculated Authorization header", done =>
            {
                const params = clone(VALID_PARAMS);
                params.headers.authorization = "CAP1-HMAC-SHA512 Credential=someId/20170702/localhost:8888/cap1_request,SignedHeaders=connection;host;x-cap-date,Signature=lEV0szOupNaXRoZPsGYziaF-liIIwA0lIyCHJCK9AxYD7fXaSAlEABgKhZOA4cw2polyV0HujGiZVU6TdQcGAW";
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done();
                    }
                );
            }
        );
        it("request X-Cap-Date is more than 15 minutes earlier than now", done =>
            {
                const params = clone(VALID_PARAMS);
                const capDate = new Date("2017-07-02T20:46:57Z");
                params.now = new Date(capDate.getTime() + 1000*60*16);
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done()
                    }
                );
            }
        );
        it("request X-Cap-Date is more than 15 minutes later than now", done =>
            {
                const params = clone(VALID_PARAMS);
                const capDate = new Date("2017-07-02T20:46:57Z");
                params.now = new Date(capDate.getTime() - 1000*60*16);
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done()
                    }
                );
            }
        );
        it("secret function calls callback with an error", done =>
            {
                const params = clone(VALID_PARAMS);
                params.secret = (_, callback) => callback(new Error("boom"));
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done()
                    }
                );
            }
        );
        it("secret function calls callback with no key material", done =>
            {
                const params = clone(VALID_PARAMS);
                params.secret = (_, callback) => callback();
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(false);
                        done()
                    }
                );
            }
        );
    });
    describe("is true if", () =>
    {
        it("request X-Cap-Date is within 15 minutes and Authorization header matches calculated Authorization header", done =>
            {
                const params = clone(VALID_PARAMS);
                params.now = new Date("2017-07-02T20:46:57Z");
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(true);
                        done()
                    }
                );
            }
        );
        it("request matches signature", done =>
            {
                const signature = cap1HmacSha512.sign(
                    {
                        headers:
                        {
                            host: "localhost:8888",
                            connection: "close"
                        },
                        httpRequestMethod: "GET",
                        key: SECRETS["someId"],
                        keyId: "someId",
                        path: "/somewhere",
                        queryString: null
                    }
                );
                const params =
                {
                    headers:
                    {
                        host: "localhost:8888",
                        connection: "close",
                        authorization: signature.authorization,
                        "x-cap-date": signature["x-cap-date"]
                    },
                    httpRequestMethod: "get",
                    path: "/somewhere",
                    queryString: null,
                    secret: (keyId, callback) => callback(undefined, SECRETS[keyId])
                };
                cap1HmacSha512.verify(params, (error, authorized) =>
                    {
                        expect(error).toBe(undefined);
                        expect(authorized).toBe(true);
                        done()
                    }
                );
            }
        );
    });
});
