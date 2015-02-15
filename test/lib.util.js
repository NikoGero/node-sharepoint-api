/*global describe, before, beforeEach, it */
/*jslint node: true, stupid: true */

var assert   = require("assert");
var Util     = require("../lib/util.js");
var Nock     = require("nock");
var fs       = require("fs");
var winston  = require("winston");

winston.clear();
//winston.add(winston.transports.Console, { colorize: true, level: 'debug' });

var nowPlusMilliseconds = function (ms) {
    "use strict";
    return new Date(new Date().getTime() + ms);
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

describe("Util", function () {
    "use strict";

    var settings = {
        username: "",
        password: "",
        host: ""
    },

        basicAuthSettings = {
            username: "",
            password: "",
            host: "",
            useBasicAuth: true,
            nonHTTPS: true
        },

        basicAuthSettings2010 = {
            host: "",
            port: 80,
            version: "2010",
            username: "",
            password: "",
            authType: "basic",
            nonHTTPS: true
        },

        ssoSettings = {
            host: "",
            port: 41053,
            authType: "sso_idp"
        },

        settingsForKidoADFS = {
            host: "",
            port: 41053,
            authType: "federation",

            username: "",
            password: "",
            wstrustEndpoint: "",
            appliesTo: "",
            tokenType: "",
            keyType: ""
        },

        settingsForKidoADFS2010 = {
            requestTimeout: 60000,
            version: "2010",
            authType: "federation",
            host: "",
            port: 8443,
            username: "",
            password: "",
            wstrustEndpoint: "",
            appliesTo: "urn:sharepoint:defaultApp",
            tokenType: "urn:oasis:names:tc:SAML:1.0:assertion",
            keyType: "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey"
        },

        token = "",

        successResponseTemplate = "<S:Envelope xmnls:S=\"\" xmnls:wst=\"\" xmnls:wsse=\"\" xmnls:wsu=\"\" xmnls=\"\"><S:Body><wst:RequestSecurityTokenResponse><wst:Lifetime><wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires></wst:Lifetime><wst:RequestedSecurityToken><wsse:BinarySecurityToken Id=\"0\">{token}</wsse:BinarySecurityToken></wst:RequestedSecurityToken></wst:RequestSecurityTokenResponse></S:Body></S:Envelope>",
        successResponse = successResponseTemplate
        .replace("{created}", new Date().toISOString())
        .replace("{expires}", nowPlusMilliseconds(15 * 60000).toISOString()) // in 15 minutes
        .replace("{token}", "authToken"),

        samlTemplate = '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">\
  <s:Header>\
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>\
    <a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>\
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">\
      <o:UsernameToken u:Id="uuid-6a13a244-dac6-42c1-84c5-cbb345b0c4c4-1">\
        <o:Username>{username}</o:Username>\
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{password}</o:Password>\
      </o:UsernameToken></o:Security>\
  </s:Header>\
  <s:Body>\
    <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">\
        <a:EndpointReference>\
            <a:Address>{endpoint}</a:Address>\
        </a:EndpointReference>\
    </wsp:AppliesTo>\
    <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>\
    <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>\
    <trust:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</trust:TokenType>\
</trust:RequestSecurityToken>\
  </s:Body>\
</s:Envelope>'.replace("{endpoint}", "https://sp.com/_forms/default.aspx?wa=wsignin1.0"),

        metadata = fs.readFileSync("./test/metadata.xml");

    beforeEach(function (done) {
        Nock.cleanAll();
        done();
    });

    describe("constructor", function () {
        it("should fail on missing setting argument", function (done) {
            try {
                var util = new Util();
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings' argument must be an object instance.", e.message);
                done();
            }
        });

        it("should fail on invalid setting argument", function (done) {
            try {
                var util = new Util("invalid setting");
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings' argument must be an object instance.", e.message);
                done();
            }
        });

        it("should fail when property 'host' is missing.", function (done) {
            try {
                var util = new Util({ });
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings.host' property is a required string.", e.message);
                done();
            }
        });

        it("should fail when property 'host' is invalid.", function (done) {
            try {
                var util = new Util({ host: 1 });
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings.host' property is a required string.", e.message);
                done();
            }
        });

        it("should fail when property 'timeout' is invalid.", function (done) {
            try {
                var util = new Util({ host: "foo", timeout: "invalid" });
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings.timeout' property must be a number.", e.message);
                done();
            }
        });

        it("should fail on invalid username", function (done) {
            try {
                var util = new Util({ host: "foo", username: 10 });
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings.username' property must be a string.", e.message);
                done();
            }
        });

        it("should fail on invalid password", function (done) {
            try {
                var util = new Util({ host: "foo", password: 10 });
                assert.ok(!util, "Had to be thrown");
            } catch (e) {
                assert.ok(e);
                assert.ok(e instanceof Error);
                assert.equal("'settings.password' property must be a string.", e.message);
                done();
            }
        });

        it("should work.", function (done) {
            var util = new Util({ host: "foo" });
            assert.ok(util);
            assert.ok(util instanceof Util);
            done();
        });
    });

    describe("authentication",  function () {
        it("should fail if invalid options", function (done) {
            var util = new Util(settings).authenticate("invalid options", function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.ok(err.message.indexOf("'options'") > -1);

                done();
            });
            assert.ok(!util);
        });

        it("should fail if username is missing", function (done) {
            var util = new Util({host: "host" }).authenticate({ }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.strictEqual(err.message, "Authentication Failure");

                done();
            });
            assert.ok(!util);
        });

        it("should fail if password is missing", function (done) {
            var util = new Util({host: "host", username: "user" }).authenticate({ username: settings.username }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);

                done();
            });
            assert.ok(!util);
        });

        it("should fail if password is invalid", function (done) {
            var util = new Util(settings).authenticate({ username: settings.username, password: "invalid password" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("Authentication Failure", err.message);

                done();
            });
            assert.ok(!util);
        });

        it("should fail if host is not allowed", function (done) {
            process.env.RUNNING_ON = "hub";
            var util = new Util({host: "localhost", username: "user", password: "pass"});
            util.authenticate(settings, function (err, result) {
                assert.ok(err);

                assert.strictEqual(err.message, "The hostname is not allowed");
                process.env.RUNNING_ON = "";
                done();
            });
        });

        it("should authenticate using MSOnline", function (done) {
            var util = new Util(settings);
            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
        });

        it("should cache authentication", function (done) {
            var util = new Util(settings);

            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.authenticate(settings, function (err2, result2) {
                    assert.ok(!err2);
                    assert.ok(result2);
                    assert.equal(result.auth, result2.auth);

                    done();
                });
            });
        });

        it("should drop expired items from auth cache", function (done) {
            var timeout = 100,

                util = new Util({ host: settings.host, timeout: timeout });

            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                setTimeout(function () {
                    util.authenticate(settings, function (err2, result2) {

                        assert.ok(!err2);
                        assert.ok(result2);
                        assert.equal("string", typeof result2.auth);
                        assert.equal(36, result2.auth.length);
                        assert.ok(result.auth !== result2.auth);

                        done();
                    });
                }, timeout + 100);
            });
        });

        it.skip("should renew expired items tokens", function (done) {
            var expirationMilliseconds = 2000,
                util = new Util(settings);

            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.query({ auth: result.auth, resource: "Lists" }, function (err, result2) {
                    assert.ok(!err, err);
                    assert.ok(result2);
                    assert.equal("bar", result2.data.foo);

                    setTimeout(function () {
                        util.query({ auth: result.auth, resource: "Users" }, function (err, result3) {
                            assert.ok(!err);
                            assert.ok(result3);
                            assert.equal("baz", result3.data.foo);

                            done();
                        });
                    }, expirationMilliseconds);
                });
            });
        });
    });

    describe("basic authentication", function () {
        it("should fail if password is invalid", function (done) {
            var util = new Util(basicAuthSettings).authenticate({ username: settings.username, password: "invalid password" }, function (err, result) {
                    assert.ok(err);
                    assert.ok(!result);
                    assert.ok(err instanceof Error);
                    assert.equal("Authentication fail.", err.message);

                    done();
                });
            assert.ok(!util);
        });

        it("should authenticate using basic auth", function (done) {
            var loginNock = new Nock("https://sp.com")
                .matchHeader('Authorization', 'Basic ' + new Buffer(settings.username + ':' + settings.password).toString('base64'))
                .get("/_api/lists")
                .reply(200, successResponse),

                util = new Util({host: "sp.com", useBasicAuth: true}).authenticate({ username: settings.username, password: settings.password }, function (err, result) {
                    assert.ok(!err);
                    assert.ok(result);
                    assert.equal("string", typeof result.auth);
                    assert.equal(36, result.auth.length);

                    loginNock.done();
                    done();
                });
            assert.ok(!util);
        });

        it("should authenticate on non-HTTPS environment using basic auth", function (done) {
            var loginNock = new Nock("http://sp.com")
                .matchHeader('Authorization', 'Basic ' + new Buffer(settings.username + ':' + settings.password).toString('base64'))
                .get("/_api/lists")
                .reply(200, successResponse),

                util = new Util({host: "sp.com", useBasicAuth: true, nonHTTPS: true}).authenticate({ username: settings.username, password: settings.password }, function (err, result) {
                    assert.ok(!err, err);
                    assert.ok(result);
                    assert.equal("string", typeof result.auth);
                    assert.equal(36, result.auth.length);

                    loginNock.done();
                    done();
                });
            assert.ok(!util);
        });

        it("should authenticate on a real environment", function (done) {
            var util = new Util(basicAuthSettings).authenticate({}, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
        });

        it("should authenticate on a real environment in SP2010", function (done) {
            var util = new Util(basicAuthSettings2010).authenticate({}, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
        });
    });

    describe("SSO authentication", function () {
        it("Should authenticate with a token", function (done) {
            var util = new Util(ssoSettings).authenticate({token: token }, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
            assert.ok(!util);
        });

        it("Should authenticate and invoke method", function (done) {
            var util = new Util(ssoSettings).get({ resource: "post", id: 1, token: token }, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                done();
            });
            assert.ok(!util);
        });
    });

    describe("Federation authentication", function () {
        it("Should request Issue security token", function (done) {
            var util = new Util(settingsForKidoADFS).authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
            assert.ok(!util);
        });

        it("Should request Issue security token for SP2010", function (done) {
            var util = new Util(settingsForKidoADFS2010).authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
            assert.ok(!util);
        });
    });

    describe("oData method", function () {
        var util,

            username = "alfa",
            password = "beta";

        beforeEach(function (done) {
            util = new Util({host: "sp.com"});
            done();
        });

        it("should fail if not auth value or user's credentials were passed within options argument.", function (done) {
            util.oData({ command: "foo" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.strictEqual(err.message, "Authentication Failure");
                done();
            });
        });

        it("should fail if 'command' property is missing.", function (done) {
            util.oData({ auth: "xyz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.ok(err.message.indexOf('options.command') > -1);
                done();
            });
        });

        it("should fail if 'command' property is invalid.", function (done) {
            util.oData({ auth: "xyz", command: 1 }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.ok(err.message.indexOf('options.command') > -1);
                done();
            });
        });

        it.skip("should be able to invoke a method passing user's credentials", function (done) {
            util.authenticate = function (options, cb) {
                assert.ok(options);
                util.cacheAuth.set("xyz", {
                    authz       : {FedAuth: "alfa", rtFa: "beta"},
                    cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                    username    : username,
                    password    : password
                });

                cb(null, {auth: "xyz"});
            };

            var spNock = new Nock("https://sp.com")
                .matchHeader('cookie', 'FedAuth=alfa;rtFa=beta')
                .get("/_api/foo")
                .reply(200, {foo: "bar"}, { "content-type": "application/json" });

            util.oData({ username: username, password: password, command: "foo" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result.data);
                assert.equal("bar", result.data.foo);

                spNock.done();
                done();
            });
        });

        it.skip("should be able to invoke a method passing auth value", function (done) {
            var item = {
                authz       : { FedAuth: "alfa", rtFa: "beta"},
                cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                username    : username,
                password    : password
            },

                spNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .get("/_api/foo")
                .reply(200, {foo: "bar"}, { "content-type": "application/json" });

            assert.ok(spNock);
            util.cacheAuth.set("xyz", item);
            util.oData({ auth: "xyz", command: "foo" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result.data);
                assert.equal("bar", result.data.foo);
                done();
            });
        });

        it.skip("should be able to invoke a method using a different HTTP method", function (done) {
            var item = {
                authz       : { FedAuth: "alfa", rtFa: "beta"},
                cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                username    : username,
                password    : password
            },

                spNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .post("/_api/foo")
                .reply(200, {foo: "bar"}, { "content-type": "application/json" }),

                digestNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .post("/_api/contextinfo", {})
                .reply(200, {d: {GetContextWebInformation: {FormDigestValue: 'abc'}}}, { "content-type": "application/json" });

            util.cacheAuth.set("xyz", item);
            util.oData({ auth: "xyz", command: "foo", method: "POST" }, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.ok(result.data);
                assert.equal("bar", result.data.foo);

                digestNock.done();
                spNock.done();
                done();
            });
        });

        it.skip("should send 'data' argument as request's body", function (done) {
            var item = {
                authz       : { FedAuth: "alfa", rtFa: "beta"},
                cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                username    : username,
                password    : password
            },

                spNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .post("/_api/foo", {baz: 1})
                .reply(200, {foo: "bar"}, { "content-type": "application/json" }),

                digestNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .post("/_api/contextinfo", {})
                .reply(200, {d: {GetContextWebInformation: {FormDigestValue: 'abc'}}}, { "content-type": "application/json" });

            util.cacheAuth.set("xyz", item);
            util.oData({ auth: "xyz", command: "foo", method: "POST", data: { baz: 1 } }, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.ok(result.data);
                assert.equal("bar", result.data.foo);

                spNock.done();
                digestNock.done();
                done();
            });
        });

        it.skip("should send 'etag' argument as request's header", function (done) {
            var item = {
                authz       : { FedAuth: "alfa", rtFa: "beta"},
                cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                username    : username,
                password    : password
            },

                spNock = new Nock("https://sp.com")
                .matchHeader('cookie', item.cookieAuthz)
                .matchHeader('if-match', "W")
                .get("/_api/foo")
                .reply(200, {foo: "bar"}, { "content-type": "application/json" });

            assert.ok(spNock);
            util.cacheAuth.set("xyz", item);
            util.oData({ auth: "xyz", command: "foo", etag: "W" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result.data);
                assert.equal("bar", result.data.foo);
                done();
            });
        });
    });

    describe("entitySets method", function () {
        var util,

            username = "alfa",
            password = "beta";

        beforeEach(function (done) {
            util = new Util({host: "sp.com"});
            done();
        });


        it.skip("should get the list of entity sets passing as options the auth token.", function (done) {
            util.cacheAuth.set("xyz", {
                authz       : { FedAuth: "alfa", rtFa: "beta"},
                cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                username    : username,
                password    : password
            });

            var spNock = new Nock("https://sp.com")
                .matchHeader('cookie', 'FedAuth=alfa;rtFa=beta')
                .get("/_api/$metadata")
                .reply(200, metadata, { "content-type": "application/xml" });

            util.entitySets({ auth: "xyz" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result instanceof Array);
                assert.ok(result.indexOf("Lists") > -1);

                spNock.done();
                done();
            });
        });


        it.skip("should get the list of entity sets passing as options the user credentials.", function (done) {
            util.authenticate = function (options, cb) {
                assert.ok(options);
                util.cacheAuth.set("xyz", {
                    authz       : { FedAuth: "alfa", rtFa: "beta"},
                    cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                    username    : username,
                    password    : password
                });

                cb(null, { auth: "xyz"});
            };

            var spNock = new Nock("https://sp.com")
                .matchHeader('cookie', 'FedAuth=alfa;rtFa=beta')
                .get("/_api/$metadata")
                .reply(200, metadata, { "content-type": "application/xml" });

            util.entitySets({ username: username, password: password }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result instanceof Array);
                assert.ok(result.indexOf("Lists") > -1);

                spNock.done();
                done();
            });
        });

        it.skip("should return an empty array if '$metadata'is not supported by sharepoint server.", function (done) {
            util.authenticate = function (options, cb) {
                assert.ok(options);
                util.cacheAuth.set("xyz", {
                    authz       : { FedAuth: "alfa", rtFa: "beta"},
                    cookieAuthz : 'FedAuth=alfa;rtFa=beta',
                    username    : username,
                    password    : password
                });

                cb(null, { auth: "xyz"});
            };

            var spNock = new Nock("https://sp.com")
                .matchHeader('cookie', 'FedAuth=alfa;rtFa=beta')
                .get("/_api/$metadata")
                .reply(404);

            util.entitySets({ username: username, password: password }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result instanceof Array);
                assert.equal(result.length, 0);

                spNock.done();
                done();
            });
        });
    });

    describe("get method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.get({ id: "bar" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.get({ resource: 10, id: "bar" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'id' property is missing", function (done) {
            util.get({ resource: "foo" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'id' property is missing.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo('bar')", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.get({resource: "foo", id: "bar"}, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo(123)", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.get({resource: "foo", id: 123}, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("query method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.query({ }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.get({ resource: 10 }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should invoke oData", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo?$filter=bar&$expand=baz&$select=xyz&$orderby=pqr&$top=rst&$skip=uvw&$inlinecount=allpages", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            var options = {
                resource    : "foo",
                filter      : "bar",
                expand      : "baz",
                select      : "xyz",
                orderBy     : "pqr",
                top         : "rst",
                skip        : "uvw",
                inLineCount : true
            };

            util.query(options, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with default values", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo?$inlinecount=none", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.query({ resource: "foo" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("links method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.links({ id: "bar", entity: "baz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.links({ resource: 10, id: "bar", entity: "baz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'id' property is missing", function (done) {
            util.links({ resource: "foo", entity: "baz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'id' property is missing.", err.message);
                done();
            });
        });

        it("should fail if 'entity' property is missing", function (done) {
            util.links({ resource: "foo", id: "bar" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'entity' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'entity' property is invalid", function (done) {
            util.links({ resource: "foo", id: "bar", entity: 10 }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'entity' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo('bar')/$links/baz", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.links({resource: "foo", id: "bar", entity: "baz" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo(123)/$links/baz", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.links({resource: "foo", id: 123, entity: "baz" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("count method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.count({ id: "bar", entity: "baz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.count({ resource: 10, id: "bar", entity: "baz" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo/$count", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.count({resource: "foo" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("GET", options.method);
                assert.equal("/foo(123)/$links/baz", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.links({resource: "foo", id: 123, entity: "baz" }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("create method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.create({ data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.create({ resource: 10, data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should invoke oData", function (done) {
            util.oData = function (options, cb) {
                assert.equal("POST", options.method);
                assert.equal("/foo", options.command);
                assert.ok(options.data);
                assert.equal("baz", options.data.bar);
                cb(null, {statusCode: 200, data: true});
            };

            util.create({ resource: "foo", data: { bar: "baz" } }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("replace method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.replace({ id: 10, data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.replace({ id: 10, resource: 10, data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'id' property is missing", function (done) {
            util.replace({ resource: "foo", data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'id' property is missing.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("PUT", options.method);
                assert.equal("/foo('xyz')", options.command);
                assert.ok(options.data);
                assert.equal("baz", options.data.bar);
                cb(null, {statusCode: 200, data: true});
            };

            util.replace({ resource: "foo", id: "xyz", data: { bar: "baz" } }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("PUT", options.method);
                assert.equal("/foo(123)", options.command);
                assert.ok(options.data);
                assert.equal("baz", options.data.bar);
                cb(null, {statusCode: 200, data: true});
            };

            util.replace({ resource: "foo", id: 123, data: { bar: "baz" } }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("update method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.update({ id: 10, data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.update({ id: 10, resource: 10, data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'id' property is missing", function (done) {
            util.update({ resource: "foo", data: { bar: "baz" } }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'id' property is missing.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("PATCH", options.method);
                assert.equal("/foo('xyz')", options.command);
                assert.ok(options.data);
                assert.equal("baz", options.data.bar);
                cb(null, {statusCode: 200, data: true});
            };

            util.update({ resource: "foo", id: "xyz", data: { bar: "baz" } }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("PATCH", options.method);
                assert.equal("/foo(123)", options.command);
                assert.ok(options.data);
                assert.equal("baz", options.data.bar);
                cb(null, {statusCode: 200, data: true});
            };

            util.update({ resource: "foo", id: 123, data: { bar: "baz" } }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("remove method", function () {
        var util;

        beforeEach(function (done) {
            util = new Util(settings);
            done();
        });

        it("should fail if 'resource' property is missing", function (done) {
            util.remove({ id: "bar" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'resource' property is invalid", function (done) {
            util.remove({ resource: 10, id: "bar" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'resource' property is missing or invalid.", err.message);
                done();
            });
        });

        it("should fail if 'id' property is missing", function (done) {
            util.remove({ resource: "foo" }, function (err, result) {
                assert.ok(err);
                assert.ok(!result);
                assert.ok(err instanceof Error);
                assert.equal("'id' property is missing.", err.message);
                done();
            });
        });

        it("should invoke oData with a string as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("DELETE", options.method);
                assert.equal("/foo('bar')", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.remove({resource: "foo", id: "bar"}, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });

        it("should invoke oData with a number as id", function (done) {
            util.oData = function (options, cb) {
                assert.equal("DELETE", options.method);
                assert.equal("/foo(123)", options.command);
                cb(null, {statusCode: 200, data: true});
            };

            util.remove({resource: "foo", id: 123}, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal(200, result.statusCode);
                assert.equal(true, result.data);
                done();
            });
        });
    });

    describe("hook method", function () {
        it("should add methods after a user was authenticated", function (done) {
            var target = {},
                util = new Util(settings);

            util.hook(target);

            assert.ok(!target.getLists);

            util.authenticate(settings, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);

                assert.equal("function", typeof target.getLists);

                done();
            });
        });

        it("should add methods if an user already was authenticated", function (done) {
            var util = new Util(settings);

            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);

                var target = {};
                util.hook(target);
                assert.equal("function", typeof target.getLists);

                done();
            });
        });

        it("Should map correct methods", function () {
            var target = {};

            before(function (done) {
                var saml = samlTemplate
                    .replace("{username}", settings.username)
                    .replace("{password}", settings.password),

                    loginNock = new Nock("https://login.microsoftonline.com")
                    .post("/extSTS.srf", saml)
                    .reply(200, successResponse),

                    authzNock = new Nock("https://sp.com")
                    .post("/_forms/default.aspx?wa=wsignin1.0", "authToken")
                    .reply(200, "", { "set-cookie": ["FedAuth=xyz", "rtFa=pqr"] }),

                    metadataNock = new Nock("https://sp.com")
                    .matchHeader('cookie', 'FedAuth=xyz;rtFa=pqr')
                    .get("/_api/$metadata")
                    .reply(200, metadata, { "content-type": "application/xml" }),

                    util = new Util(settings);

                util.get = function (options, cb) { cb(null, "get-" + options.resource); };
                util.query = function (options, cb) { cb(null, "query-" + options.resource); };
                util.links = function (options, cb) { cb(null, "links-" + options.resource); };
                util.count = function (options, cb) { cb(null, "count-" + options.resource); };
                util.create = function (options, cb) { cb(null, "create-" + options.resource); };
                util.replace = function (options, cb) { cb(null, "replace-" + options.resource); };
                util.update = function (options, cb) { cb(null, "update-" + options.resource); };
                util.remove = function (options, cb) { cb(null, "remove-" + options.resource); };

                util.authenticate({ username: settings.username, password: settings.password }, function (err, result) {
                    assert.ok(!err);
                    assert.ok(result);

                    util.hook(target);

                    target.getLists({}, function (err, res) {
                        assert.ok(!err);
                        assert.equal("get-Lists", res);

                        target.queryLists({}, function (err, res) {
                            assert.ok(!err);
                            assert.equal("query-Lists", res);

                            target.linksLists({}, function (err, res) {
                                assert.ok(!err);
                                assert.equal("links-Lists", res);

                                target.countLists({}, function (err, res) {
                                    assert.ok(!err);
                                    assert.equal("count-Lists", res);

                                    target.createLists({}, function (err, res) {
                                        assert.ok(!err);
                                        assert.equal("create-Lists", res);

                                        target.replaceLists({}, function (err, res) {
                                            assert.ok(!err);
                                            assert.equal("replace-Lists", res);

                                            target.updateLists({}, function (err, res) {
                                                assert.ok(!err);
                                                assert.equal("update-Lists", res);

                                                target.removeLists({}, function (err, res) {
                                                    assert.ok(!err);
                                                    assert.equal("remove-Lists", res);

                                                    loginNock.done();
                                                    authzNock.done();
                                                    metadataNock.done();
                                                    done();
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });

    describe("lookupMethod method", function () {
        describe("after methods were hooked", function () {
            var target,
                util;

            beforeEach(function (done) {
                target = {};
                util = new Util(settings);

                util.hook(target);

                assert.ok(!target.getLists);
                util.authenticate(settings, function (err, result) {
                    assert.ok(!err);
                    assert.ok(result);
                    done();
                });

            });

            it("should return the method if it does exist", function (done) {
                util.lookupMethod(target, "getLists", function (err, method) {
                    assert.ok(!err);
                    assert.equal(typeof method, "function");
                    done();
                });
            });

            it("should return null if the method does not exist", function (done) {
                util.lookupMethod(target, "invaid method name", function (err, method) {
                    assert.ok(!err);
                    assert.ok(!method);
                    done();
                });
            });
        });

        describe("if methods where not hooked yet", function () {
            var target,
                util;

            beforeEach(function () {
                target = {};
                util = new Util(settings);
                util.hook(target);

                assert.ok(!target.queryLists);
            });

            it("if the method does exist, should wait until all methods were hooked and then return the method.", function (done) {
                // the method returned is a wrapper, so metadata will be retrieved after the wrapper was invoked. 
                util.lookupMethod(target, "queryLists", function (err, method) {

                    assert.ok(!err);
                    assert.equal(typeof method, "function");

                    // mock query method
                    util.query = function (options, queryCb) {
                        assert.ok(options);
                        queryCb(null, []);
                    };

                    method(settings, function (err, result) {
                        assert.ok(!err);
                        assert.ok(result);
                        done();
                    });
                });
            });

            it("if the method does not exist,should wait until all methods were hooked and return null.", function (done) {
                // the method returned is a wrapper, so metadata will be retrieved after the wrapper was invoked. 
                util.lookupMethod(target, "invalid", function (err, method) {

                    assert.ok(!err);
                    assert.equal(typeof method, "function");

                    method(settings, function (err, result) {
                        assert.ok(!err);
                        assert.ok(!result);
                        done();
                    });
                });
            });
        });
    });

    describe("methods not mocked", function () {
        it("should invoke odata with MSOnline auth", function (done) {
            var util = new Util(settings);
            util.authenticate(settings, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.oData({ auth: result.auth, command: "/lists/getbytitle('Tasks')/items"}, function (err, result) {
                    assert.ok(!err);
                    assert.ok(result);
                    assert.ok(result.data);
                    assert.ok(result.data.d);
                    assert.ok(result.data.d.results);
                    assert.ok(result.data.d.results.length > 0);

                    done();
                });
            });
        });

        it("should create an item and delete it", function (done) {
            var util = new Util(basicAuthSettings),
                id;
            util.create(
                {
                    'resource': 'Team_x0020_DiscussionListItems',
                    'data': {
                        '__metadata': {
                            'type': 'SP.Data.Team_x0020_DiscussionListItem'
                        },
                        'Title': 'Preferred IDE',
                        'Body': '<div><p>Which is your Preferred IDE for HTML and Hybrid ?'
                    }
                },
                function (err, data) {
                    assert.ifError(err);
                    assert.ok(data);
                    assert.strictEqual(data.statusCode, 201);
                    assert.ok(data.data.d.Id);

                    id = data.data.d.Id;

                    util.update(
                        {
                            'resource': 'Team_x0020_DiscussionListItems',
                            'id': id,
                            'data': {
                                '__metadata': {
                                    'type': 'SP.Data.Team_x0020_DiscussionListItem'
                                },
                                'Title': 'Modified Preferred IDE',
                                'Body': '<div><p>Which is your ALTERNATIVE IDE for HTML and Hybrid ?'
                            }
                        },
                        function (err, data) {
                            assert.ifError(err);
                            assert.strictEqual(data.statusCode, 204);

                            util.remove(
                                {
                                    'resource': 'Team_x0020_DiscussionListItems',
                                    'id': id
                                },
                                function (err, data) {
                                    assert.ifError(err);
                                    assert.strictEqual(data.statusCode, 200);

                                    done();
                                }
                            );
                        }
                    );
                }
            );
        });

        it("should invoke ProcessQuery", function (done) {
            var util = new Util(basicAuthSettings),
                xml = '<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009" SchemaVersion="15.0.0.0" LibraryVersion="15.0.0.0" ApplicationName="Javascript Library"><Actions><Query Id="75" ObjectPathId="6"><Query SelectAllProperties="true"><Properties><Property Name="AllowContentTypes" ScalarProperty="true" /><Property Name="BaseTemplate" ScalarProperty="true" /><Property Name="BaseType" ScalarProperty="true" /><Property Name="ContentTypesEnabled" ScalarProperty="true" /><Property Name="Created" ScalarProperty="true" /><Property Name="DefaultContentApprovalWorkflowId" ScalarProperty="true" /><Property Name="Description" ScalarProperty="true" /><Property Name="Direction" ScalarProperty="true" /><Property Name="DocumentTemplateUrl" ScalarProperty="true" /><Property Name="DraftVersionVisibility" ScalarProperty="true" /><Property Name="EnableAttachments" ScalarProperty="true" /><Property Name="EnableFolderCreation" ScalarProperty="true" /><Property Name="EnableMinorVersions" ScalarProperty="true" /><Property Name="EnableModeration" ScalarProperty="true" /><Property Name="EnableVersioning" ScalarProperty="true" /><Property Name="EntityTypeName" ScalarProperty="true" /><Property Name="ForceCheckout" ScalarProperty="true" /><Property Name="HasExternalDataSource" ScalarProperty="true" /><Property Name="Hidden" ScalarProperty="true" /><Property Name="Id" ScalarProperty="true" /><Property Name="ImageUrl" ScalarProperty="true" /><Property Name="IrmEnabled" ScalarProperty="true" /><Property Name="IrmExpire" ScalarProperty="true" /><Property Name="IrmReject" ScalarProperty="true" /><Property Name="IsApplicationList" ScalarProperty="true" /><Property Name="IsCatalog" ScalarProperty="true" /><Property Name="IsPrivate" ScalarProperty="true" /><Property Name="ItemCount" ScalarProperty="true" /><Property Name="LastItemDeletedDate" ScalarProperty="true" /><Property Name="LastItemModifiedDate" ScalarProperty="true" /><Property Name="ListItemEntityTypeFullName" ScalarProperty="true" /><Property Name="MultipleDataList" ScalarProperty="true" /><Property Name="NoCrawl" ScalarProperty="true" /><Property Name="ParentWebUrl" ScalarProperty="true" /><Property Name="ServerTemplateCanCreateFolders" ScalarProperty="true" /><Property Name="TemplateFeatureId" ScalarProperty="true" /><Property Name="Title" ScalarProperty="true" /></Properties></Query></Query><ObjectPath Id="77" ObjectPathId="76" /><Method Name="SetFieldValue" Id="78" ObjectPathId="76"><Parameters><Parameter Type="String">Title</Parameter><Parameter Type="String">Using JS Client OM from postman!</Parameter></Parameters></Method><Method Name="SetFieldValue" Id="79" ObjectPathId="76"><Parameters><Parameter Type="String">Body</Parameter><Parameter Type="String">test from JS Client OM Body!</Parameter></Parameters></Method><Method Name="Update" Id="80" ObjectPathId="76" /><Query Id="81" ObjectPathId="76"><Query SelectAllProperties="true"><Properties><Property Name="Title" ScalarProperty="true" /><Property Name="Body" ScalarProperty="true" /></Properties></Query></Query></Actions><ObjectPaths><Identity Id="6" Name="740c6a0b-85e2-48a0-a494-e0f1759d4aa7:site:2e854f38-7de2-44b7-914d-f484e63af675:web:4f32215b-721f-41d1-84ce-dec89144142b:list:7fda9130-a25a-4293-8561-b1f481f62764" /><StaticMethod Id="76" Name="CreateNewDiscussion" TypeId="{16f43e7e-bf35-475d-b677-9dc61e549339}"><Parameters><Parameter ObjectPathId="6" /><Parameter Type="Null" /></Parameters></StaticMethod></ObjectPaths></Request>';

            util.processQuery({data: xml}, function (err, data) {
                assert.ifError(err);
                assert.ok(data);
                assert.strictEqual(data.statusCode, 200);

                done();
            });
        });

        var invokeCommandLists = function (util, auth, done) {
            util.oData({ auth: auth, command: "/lists"}, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.ok(result.data);
                assert.ok(result.data.d);
                assert.ok(result.data.d.results);
                assert.ok(result.data.d.results.length > 0);

                done();
            });
        };

        it("Should authenticate with a token", function (done) {
            var util = new Util(ssoSettings);
            util.authenticate({ token: token }, function (err, result) {
                assert.ok(!err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                invokeCommandLists(util, result.auth, done);
            });
        });

        it("Should auth with Federation and invoke lists command", function (done) {
            var util = new Util(settingsForKidoADFS);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                invokeCommandLists(util, result.auth, done);
            });
        });

        it("Should auth with Federation and getEntitySets", function (done) {
            var util = new Util(settingsForKidoADFS);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.entitySets({ auth: result.auth}, function (err, result) {
                    assert.ifError(err);
                    assert.ok(result);
                    assert.ok(result.length > 0);

                    done();
                });
            });
        });

        it("Should auth with Federation and getEntitySets for SP2010", function (done) {
            var util = new Util(settingsForKidoADFS2010);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.entitySets({ auth: result.auth}, function (err, result) {
                    assert.ifError(err);
                    assert.ok(result);
                    assert.ok(result.length > 0);

                    done();
                });
            });
        });

        it("Should auth with Basic and getEntitySets for SP2010", function (done) {
            var util = new Util(basicAuthSettings2010);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.entitySets({ auth: result.auth}, function (err, result) {
                    assert.ifError(err);
                    assert.ok(result);
                    assert.ok(result.length > 0);

                    done();
                });
            });
        });

        it("Should auth with Federation and invoke a command for SP2010", function (done) {
            var util = new Util(settingsForKidoADFS2010);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.query({ auth: result.auth, resource: "Posts"}, function (err, result) {
                    assert.ifError(err);
                    assert.ok(result);
                    assert.ok(result.data);
                    assert.ok(result.data.d);
                    assert.ok(result.data.d.results);
                    assert.ok(result.data.d.results.length > 0);

                    done();
                });
            });
        });

        it("Should auth with Federation and create, update and delete an item in SP2010", function (done) {
            var util = new Util(settingsForKidoADFS2010),
                id;
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                util.create(
                    {
                        'resource': 'Posts',
                        'data': {
                            'Title': 'Preferred IDE',
                            'Body': '<div><p>Which is your Preferred IDE for HTML and Hybrid ?'
                        }
                    },
                    function (err, data) {
                        assert.ifError(err);
                        assert.ok(data);
                        assert.strictEqual(data.statusCode, 201);
                        assert.ok(data.data.d.Id);

                        id = data.data.d.Id;

                        util.update(
                            {
                                'resource': 'Posts',
                                'id': id,
                                'data': {
                                    'Title': 'Modified Preferred IDE',
                                    'Body': '<div><p>Which is your ALTERNATIVE IDE for HTML and Hybrid ?'
                                }
                            },
                            function (err, data) {
                                assert.ifError(err);
                                assert.strictEqual(data.statusCode, 204);

                                util.remove(
                                    {
                                        'resource': 'Posts',
                                        'id': id
                                    },
                                    function (err, data) {
                                        assert.ifError(err);
                                        assert.strictEqual(data.statusCode, 204);

                                        done();
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });

        it("Should auth with Federation and invoke process query for SP2010", function (done) {
            var util = new Util(basicAuthSettings2010);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal("string", typeof result.auth);
                assert.equal(36, result.auth.length);

                var xml = '<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009" SchemaVersion="14.0.0.0" LibraryVersion="14.0.7007.1000" ApplicationName="Javascript Library"><Actions><ObjectPath Id="7" ObjectPathId="6" /><ObjectPath Id="9" ObjectPathId="8" /><Query Id="10" ObjectPathId="8"><Query SelectAllProperties="true"><Properties /></Query></Query></Actions><ObjectPaths><StaticProperty Id="6" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current" /><Property Id="8" ParentId="6" Name="Web" /></ObjectPaths></Request>';
                util.processQuery({auth: result.auth, data: xml}, function (err, data) {
                    assert.ifError(err);
                    assert.ok(data);
                    assert.strictEqual(data.statusCode, 200);

                    done();
                });
            });
        });
    });
});
