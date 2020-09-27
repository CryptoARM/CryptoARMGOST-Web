"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/исходные";
var DEFAULT_OUT_PATH = "test/полученные";

describe("Cipher 2012-256 with russian folder", function () {
    var cipher;
    var ris, ri;
    var store, cert, key;
    var certFile = "TrustedCrypto2012-256.cer";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        cipher = new trusted.pki.Cipher();
        assert.equal(cipher !== null, true);
    });

    it("recipients", function () {
        var certs = new trusted.pki.CertificateCollection();

        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.cer", trusted.DataFormat.PEM));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER));
        assert.equal(certs.length, 2);

        cipher.recipientsCerts = certs;
    });

    it("encrypt PEM", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256.txt.enc", trusted.EncryptAlg.GOST_28147, trusted.DataFormat.PEM);
    });

    it("encrypt DER", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256_der.txt.enc", trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
    });


    it("decrypt PEM", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym2012-256.txt.enc", DEFAULT_OUT_PATH + "/decAssym2012-256.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt DER", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym2012-256_der.txt.enc", DEFAULT_OUT_PATH + "/decAssym2012-256_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });
});


