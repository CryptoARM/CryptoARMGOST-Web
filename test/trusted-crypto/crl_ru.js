"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/исходные";
var DEFAULT_OUT_PATH = "test/полученные";

describe("CRL with russian folder", function () {
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

    it("save", function () {
        crl.save(DEFAULT_OUT_PATH + "/out.crl");

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/out.crl");

        assert.equal(res.toString() === out.toString(), true, "Resource and out CRL file diff");
    });

});
