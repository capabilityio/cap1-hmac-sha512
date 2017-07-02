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
