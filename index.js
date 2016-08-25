var express = require('express'),
    app = express(),
    http = require('http'),
    httpServer = http.Server(app);
var expressJwt = require('express-jwt');
var jwt = require('jsonwebtoken');

require('es6-promise').polyfill();
require('isomorphic-fetch');

const privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n-----END RSA PRIVATE KEY-----";
const publicKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n-----END PUBLIC KEY-----";

app.use('/app', express.static(__dirname + '/app'));

// Validate JWT token for everything except /app/ and /token
app.use(expressJwt({ secret: publicKey, algorithms: ['RS256'] }).unless({ path: [/^\/(app|legacy)\/.*$/, '/token'] }));

// Make sure the requestToken header is set if the JWT token validated
app.use(function (req, res, next) {
    if(req.user && !req.header("appRequestToken")) {
        res.status(401).end("appRequestToken is missing");
    } else {
        next();
    }
});

app.use('/api', function (req, res) {
    fetch("http://localhost:3000/legacy" + req.url, {
        headers: {
            "Authorization": "Session " + req.user.sid,
            "RequestToken": req.header('appRequestToken')
        }
    })
        .then(function (response) {
            if (response.status >= 400) {
                throw new Error("Bad response from server");
            }
            return response.json();
        })
        .then(function (data) {
            res.json(data);
        });
});



app.get('/token', function (req, res) {
    var token = jwt.sign({
        sub: "test",
        sid: "abcde"
    }, privateKey, {
        algorithm: 'RS256',
        issuer: 'myApp',
        expiresIn: "2h"
    });
    res.json({
        id_token: token,
    });
});

app.use('/legacy', function (req, res) {
    res.json({
        stuff: req.url,
        headers: req.headers
    });
});

app.listen(3000);
