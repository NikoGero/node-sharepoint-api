/*global describe, it */
/*jslint node: true, stupid: true */

var assert   = require("assert");
var Util     = require("../lib/util.js");
var winston = require("winston");

winston.clear();
//winston.add(winston.transports.Console, { colorize: true, level: 'debug' });

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

describe("Util", function () {
    "use strict";

    var ntlmAuthSettings = {
        host: "",
        port: 12345,
        username: "",
        password: "",
        authType: "ntlm",
        nonHTTPS: true
    },

        ntlmAuthSettings2010 = {
            host: "",
            port: 8443,
            version: "",
            username: "",
            password: "",
            authType: "ntlm",
            nonHTTPS: false
        };

    describe("NTLM authentication", function () {
        it("Should authenticate", function (done) {
            var util = new Util(ntlmAuthSettings).authenticate({}, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.equal('string', typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
        });

        it("Should authenticate in SP2010", function (done) {
            var util = new Util(ntlmAuthSettings2010).authenticate({}, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);
                assert.equal('string', typeof result.auth);
                assert.equal(36, result.auth.length);

                done();
            });
        });

        it("Should invoke a method", function (done) {
            var query = {
                "resource": "SP.UserProfiles.PeopleManager/GetMyProperties",
                "select": "PictureUrl,AccountName"
            };
            var util = new Util(ntlmAuthSettings).query(query, function (err, result) {
                assert.ok(!err, err);
                assert.ok(result);

                assert.strictEqual(result.statusCode, 200);
                assert.strictEqual(result.data.d.AccountName, "WIN-V720IVH6N8J\\Administrator");
                assert.strictEqual(result.data.d.PictureUrl, "http://win-v720ivh6n8j:80/my/User%20Photos/Profile%20Pictures/administrator_MThumb.jpg?t=63547707327");

                done();
            });
        });

        it("should create an item and delete it", function (done) {
            var util = new Util(ntlmAuthSettings),
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

        it("should create an item and delete it caching user credentials", function (done) {
            var newConfig = {};
            newConfig.host = ntlmAuthSettings.host;
            newConfig.port = ntlmAuthSettings.port;
            newConfig.authType = ntlmAuthSettings.authType;
            newConfig.nonHTTPS = ntlmAuthSettings.nonHTTPS;

            var util = new Util(newConfig),
                id;
            util.authenticate({username: ntlmAuthSettings.username, password: ntlmAuthSettings.password},
                function (err, result) {
                    assert.ifError(err);
                    assert.ok(result);
                    assert.equal('string', typeof result.auth);
                    assert.equal(36, result.auth.length);

                    util.create(
                        {
                            'auth': result.auth,
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

                            util.remove(
                                {
                                    'auth': result.auth,
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
                });
        });

        it("Should auth with NTLM and invoke a command for SP2010", function (done) {
            var util = new Util(ntlmAuthSettings2010);
            util.authenticate({}, function (err, result) {
                assert.ifError(err);
                assert.ok(result);
                assert.equal('string', typeof result.auth);
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
    });
});
