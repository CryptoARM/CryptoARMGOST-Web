"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("PKCS12 2012-256", function () {
    var pkcs12;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        pkcs12 = new trusted.pki.PKCS12();
        assert.equal(pkcs12 !== null, true);
    });

    it("load", function () {
        pkcs12.load(DEFAULT_RESOURCES_PATH + "/pfx2012-256.pfx");
    });

    it("save", function () {
        pkcs12.save(DEFAULT_OUT_PATH + "/out2012-256.pfx");

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/pfx2012-256.pfx");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/out2012-256.pfx");

        assert.equal(res.toString() === out.toString(), true, "Resource and out pfx file diff");
    });

    it("create", function () {
        var cert;
        var p12Res;

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer", trusted.DataFormat.DER);
        assert.equal(cert !== null, true);

        p12Res = trusted.utils.Csp.certToPkcs12(cert, true, "1");
        assert.equal(p12Res !== null, true, "123");
    });
});

describe("PKCS12 2012-512", function () {
    var pkcs12;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        pkcs12 = new trusted.pki.PKCS12();
        assert.equal(pkcs12 !== null, true);
    });

    it("load", function () {
        pkcs12.load(DEFAULT_RESOURCES_PATH + "/pfx2012-512.pfx");
    });

    it("save", function () {
        pkcs12.save(DEFAULT_OUT_PATH + "/out2012-512.pfx");

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/pfx2012-512.pfx");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/out2012-512.pfx");

        assert.equal(res.toString() === out.toString(), true, "Resource and out pfx file diff");
    });

    it("create", function () {
        var cert;
        var p12Res;

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-512.cer", trusted.DataFormat.DER);
        assert.equal(cert !== null, true);

        p12Res = trusted.utils.Csp.certToPkcs12(cert, true, "1");
        assert.equal(p12Res !== null, true, "123");
    });
});
