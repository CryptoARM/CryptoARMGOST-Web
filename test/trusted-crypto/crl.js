 "use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("CRL", function () {
    var crl;

    before(function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        crl = new trusted.pki.CRL();
        assert.equal(crl !== null, true);
    });

    it("load", function () {
        crl.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
    });

    it("import", function () {
        var icrl = new trusted.pki.CRL();
        var data = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
	    icrl.import(data);
        assert.equal(typeof (icrl.version), "number", "Bad version value");
    });

    it("export", function () {
        var buf;

        buf = crl.export();
        assert.equal(Buffer.isBuffer(buf), true);
    });

    it("duplicate", function () {
        var crl1, crl2;

        crl1 = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
        crl2 = crl1.duplicate();
        assert.equal(crl1.thumbprint === crl2.thumbprint, true, "CRL are not equals");
    });

    it("equals", function () {
        var crl1, crl2;

        crl1 = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
        crl2 = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2001.crl");
        assert.equal(crl1.equals(crl1), true, "CRL are equals");
        assert.equal(crl1.equals(crl2), false, "CRL are not equals");
    });

    it("save", function () {
        crl.save(DEFAULT_OUT_PATH + "/out.crl");

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/out.crl");

        assert.equal(res.toString() === out.toString(), true, "Resource and out CRL file diff");
    });

    it("hash", function () {
        var crl1 = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");

        var hash1 = crl1.hash();
        var hash2 = crl1.hash("sha1");
        var hash3 = crl1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

    it("params", function () {
        assert.equal(typeof (crl.version), "number", "Bad version value");
        assert.equal(typeof (crl.thumbprint), "string", "Bad thumbprint value");
        assert.equal(typeof (crl.signatureAlgorithm), "string", "Bad signatureAlgorithme value");
        assert.equal(typeof (crl.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (crl.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (crl.lastUpdate), "object", "Bad lastUpdate value");
        assert.equal(typeof (crl.nextUpdate), "object", "Bad nextUpdate value");
        assert.equal(typeof (crl.thumbprint), "string", "Bad thumbprint value");
        assert.equal(typeof (crl.authorityKeyid), "string", "Bad authorityKeyid value");
        assert.equal(typeof (crl.crlNumber), "number", "Bad CRLnumber value");
    });

    it("verify", function () {
        var res = trusted.utils.Csp.verifyCRL(crl);
        assert.equal(res, false, "Not valid");
    });
});
