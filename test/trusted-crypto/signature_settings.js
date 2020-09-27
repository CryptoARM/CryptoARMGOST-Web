"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("TimestampParams", function () {
    var tspParams;
    var cadesEnabled;

    before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
    });

    it("init", function () {
        if (!cadesEnabled)
            this.skip();

        tspParams = new trusted.cms.TimestampParams();
        assert.equal(tspParams !== null, true);
    });

    //stampType
    it("StampType type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (tspParams.stampType), "number", "Bad result value type");
    });

    it("StampType value", function () {
        if (!cadesEnabled)
            this.skip();

        tspParams.stampType = trusted.cms.StampType.stContent;
        assert.equal(tspParams.stampType, trusted.cms.StampType.stContent, "Wrong value");
    });

    //connSettings
    it("connSettings value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (tspParams.connSettings), "object", "Bad result value type");
    });

    it("connSettings value", function () {
        if (!cadesEnabled)
            this.skip();

        tspParams.connSettings = new trusted.utils.ConnectionSettings();
        assert.equal(typeof(tspParams.connSettings), "object", "Wrong address value");
    });

    //tspHashAlg
    it("tspHashAlg value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (tspParams.tspHashAlg), "string", "Bad result value type");
    });

    it("tspHashAlg value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(tspParams.tspHashAlg, "", "Wrong empty value");
        tspParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        assert.equal(tspParams.tspHashAlg, "1.2.643.7.1.1.2.2", "Wrong OID value");
    });
});

describe("CadesParams", function () {
    var cadesParams;
    var cadesEnabled;

    before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
    });

    it("init", function () {
        if (!cadesEnabled)
            this.skip();

        cadesParams = new trusted.cms.CadesParams();
        assert.equal(cadesParams !== null, true);
    });

    //cadesType
    it("cadesType type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (cadesParams.cadesType), "number", "Bad result value type");
    });

    it("cadesType value", function () {
        if (!cadesEnabled)
            this.skip();

        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        assert.equal(cadesParams.cadesType, trusted.cms.CadesType.ctCadesXLT1, "Wrong value");
    });

    //connSettings
    it("connSettings value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (cadesParams.connSettings), "object", "Bad result value type");
    });

    it("connSettings value", function () {
        if (!cadesEnabled)
            this.skip();

        cadesParams.connSettings = new trusted.utils.ConnectionSettings();
        assert.equal(typeof (cadesParams.connSettings), "object", "Wrong address value");
    });

    //tspHashAlg
    it("tspHashAlg value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (cadesParams.tspHashAlg), "string", "Bad result value type");
    });

    it("tspHashAlg value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(cadesParams.tspHashAlg, "", "Wrong empty value");
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        assert.equal(cadesParams.tspHashAlg, "1.2.643.7.1.1.2.2", "Wrong OID value");
    });

    //ocspSettings
    it("ocspSettings value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (cadesParams.ocspSettings), "object", "Bad result value type");
    });

    it("ocspSettings value", function () {
        if (!cadesEnabled)
            this.skip();

        cadesParams.ocspSettings = new trusted.utils.ConnectionSettings();
        assert.equal(typeof (cadesParams.ocspSettings), "object", "Wrong address value");
    });

});
