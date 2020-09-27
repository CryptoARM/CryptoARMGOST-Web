"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("OID", function () {
    it("create", function () {

        var oid = new trusted.pki.Oid("keyUsage");

        assert.equal(oid.value, "2.5.29.15");
        //assert.equal(oid.longName, "commonName");
        assert.equal(oid.shortName, "keyUsage");
    });

    // it("create with error", function() {
    //     assert.throws(function() {
    //         return new trusted.pki.Oid("2.5.4.3_error");
    //     });
    // });
});
