"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("Connection settings", function () {
    var connSettings;
    var cadesEnabled;

    before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
    });

    it("init", function () {
        if (!cadesEnabled)
            this.skip();

        connSettings = new trusted.utils.ConnectionSettings();
        assert.equal(connSettings !== null, true);
    });

    //AuthType
    it("AuthType value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.AuthType), "number", "Bad result value type");
    });

    it("AuthType value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.AuthType, 0, "Wrong empty value");
        connSettings.AuthType = 2;
        assert.equal(connSettings.AuthType, 2, "Wrong value");
    });

    //Address
    it("Address value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.Address), "string", "Bad result value type");
    });

    it("Address value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.Address, "", "Wrong empty value");
        connSettings.Address = "http://example.com";
        assert.equal(connSettings.Address, "http://example.com", "Wrong address value");
    });

    //UserName
    it("UserName value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.UserName), "string", "Bad result value type");
    });

    it("UserName value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.UserName, "", "Wrong empty value");
        connSettings.UserName = "MyLogin";
        assert.equal(connSettings.UserName, "MyLogin", "Wrong User Name value");
    });

    //Password
    it("Password value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.Password), "string", "Bad result value type");
    });

    it("Password value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.Password, "", "Wrong empty value");
        connSettings.Password = "MySecretPassword";
        assert.equal(connSettings.Password, "MySecretPassword", "Wrong password value");
    });

    //ClientCert
    it("ClientCert value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.ClientCertificate), "undefined", "Bad result value type");
    });

    it("ClientCert initialized value type", function () {
        if (!cadesEnabled)
            this.skip();

        connSettings.ClientCertificate = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer");
        assert.equal(typeof (connSettings.ClientCertificate), "object", "Bad initialized value type");
    });

    it("ClientCert value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.ClientCertificate.compare(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer")), 0, "Certificate differs from source");
    });

    it("ClientCert clear certificate", function () {
        if (!cadesEnabled)
            this.skip();

        connSettings.ClientCertificate = undefined;
        assert.equal(typeof (connSettings.ClientCertificate), "undefined", "Bad cleared value type");
    });

    //ProxyAuthType
    it("ProxyAuthType value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.ProxyAuthType), "number", "Bad result value type");
    });

    it("ProxyAuthType value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.ProxyAuthType, 0, "Wrong empty value");
        connSettings.ProxyAuthType = 2;
        assert.equal(connSettings.ProxyAuthType, 2, "Wrong value");
    });

    //ProxyAddress
    it("ProxyAddress value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.ProxyAddress), "string", "Bad result value type");
    });

    it("ProxyAddress value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.ProxyAddress, "", "Wrong empty value");
        connSettings.ProxyAddress = "proxy.local";
        assert.equal(connSettings.ProxyAddress, "proxy.local", "Wrong proxy address value");
    });

    //ProxyUserName
    it("ProxyUserName value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.ProxyUserName), "string", "Bad result value type");
    });

    it("ProxyUserName value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.ProxyUserName, "", "Wrong empty value");
        connSettings.ProxyUserName = "ProxyLogin";
        assert.equal(connSettings.ProxyUserName, "ProxyLogin", "Wrong proxy User Name value");
    });

    //ProxyPassword
    it("ProxyPassword value type", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(typeof (connSettings.ProxyPassword), "string", "Bad result value type");
    });

    it("ProxyPassword value", function () {
        if (!cadesEnabled)
            this.skip();

        assert.equal(connSettings.ProxyPassword, "", "Wrong empty value");
        connSettings.ProxyPassword = "ProxySecretPassword";
        assert.equal(connSettings.ProxyPassword, "ProxySecretPassword", "Wrong proxy password value");
    });
});

