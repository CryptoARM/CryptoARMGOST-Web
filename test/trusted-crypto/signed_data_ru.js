"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/исходные";
var DEFAULT_OUT_PATH = "test/полученные";

describe("SIGN 2012-256 with russian folder", function () {
    var certFile = "TrustedCrypto2012-256.cer";
    var attachSignFile = "testsig2012-256_at.sig";
    

    describe("SIGNED_DATA: attached in PEM", function () {
            var cert;
            var cms;
            var sd;
            
			before(function () {
                try {
                    fs.statSync(DEFAULT_OUT_PATH).isDirectory();
                } catch (err) {
                    fs.mkdirSync(DEFAULT_OUT_PATH);
                }

                cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
            });

            it("Sign data", function () {
                var signer;
                var policies;

                sd = new trusted.cms.SignedData();

                sd.policies = [];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            });

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

            });

            it("Verify attached signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });

            it("load", function () {
                var signers;
                var signer;
                var signerId;

                cms = new trusted.cms.SignedData();
                cms.load(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify attached signature", function () {
                assert.equal(cms.isDetached(), false, "Dettached");
            });
    });       
});

