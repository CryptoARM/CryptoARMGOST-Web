"use strict";

var assert = require("assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var trusted = require("../index.js");
var childProcess = require("child_process");

var DEFAULT_RESOURCES_PATH = "test/resources/KU";
var DEFAULT_OUT_PATH = "test/out";
var DEFAULT_CERTSTORE_PATH = "test/CertStore";

var compare_app = os.type() === "Windows_NT" ? "fc" : "diff";
var compare_params = os.type() === "Windows_NT" ? "" : "--strip-trailing-cr";

describe("KU-tests", function () {

    const kuList = [
        {
            name: "KU-digitalSignature-keyEncipherment",
            sign: true, addsign: true, verify: true, encrypt: true, decrypt: true
        },
        {
            name: "KU-digitalSignature",
            sign: true, addsign: true, verify: true, encrypt: false, decrypt: false
        },
        {
            name: "KU-keyEncipherment",
            sign: false, addsign: false, verify: false, encrypt: true, decrypt: true
        },
        {
            name: "KU-none",
            sign: false, addsign: false, verify: false, encrypt: false, decrypt: false
        }
    ];

    var cert;
    var fileForTests = "KU-tests.txt";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    kuList.forEach(function (test) {
        describe(test.name, function () {
            it("Init", function () {
                cert = new trusted.pki.Certificate();
                cert.load(DEFAULT_RESOURCES_PATH + "/" + test.name + ".cer");
                assert.equal(typeof (cert.version), "number", "Bad version value");
            });

            it("Sign", function () {
                var cmsSign = new trusted.cms.SignedData();
                cmsSign.policies = [];
                //cmsSign.content = {
                //    type: trusted.cms.SignedDataContentType.url,
                //    data: DEFAULT_RESOURCES_PATH + "/" + fileForTests
                //};
                cmsSign.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Key usage tests: " + test.name
                };

                if (test.sign) {
                    assert.doesNotThrow(function () {
                        return cmsSign.sign(cert);
                    }, "Signing must be sucessfull");
                }
                else {
                    assert.throws(function () {
                        return cmsSign.sign(cert);
                    }, "Signing must fail");
                }

                // Save sign for test reasons
                //cmsSign.save(DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.sig", trusted.DataFormat.DER);
            });

            it("Add sign", function () {
                var cmsAdd = new trusted.cms.SignedData();
                cmsAdd.load(DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.sig", trusted.DataFormat.DER);
                cmsAdd.policies = [];

                if (test.sign) {
                    assert.doesNotThrow(function () {
                        return cmsAdd.sign(cert);
                    }, "Add sign must be sucessfull");
                }
                else {
                    assert.throws(function () {
                        return cmsAdd.sign(cert);
                    }, "Add sign must fail");
                }
            });

            it("Verify", function () {
                var cmsVerify = new trusted.cms.SignedData();
                cmsVerify.load(DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.sig", trusted.DataFormat.DER);
                assert.equal(cmsVerify.verify(), test.verify, test.verify ? "Signature must be valid" : "Verification must fail");
                assert.equal(cmsVerify.verify(cmsVerify.signers(0)), test.verify, test.verify ? "Signer must be valid" : "Signer verification must fail");
            });

            it("Verify detached", function () {
                var cmsVerifyDet = new trusted.cms.SignedData();
                cmsVerifyDet.load(DEFAULT_RESOURCES_PATH + "/" + test.name + "_det.txt.sig", trusted.DataFormat.DER);
                cmsVerifyDet.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Key usage tests: " + test.name + " - detached"
                };
                assert.equal(cmsVerifyDet.verify(), test.verify, test.verify ? "Signature must be valid" : "Verification must fail");
                assert.equal(cmsVerifyDet.verify(cmsVerifyDet.signers(0)), test.verify, test.verify ? "Signer must be valid" : "Signer verification must fail");
            });

            // TODO: verify CAdES

            it("Encrypt", function () {
                var cipher = new trusted.pki.Cipher();
                var recipients = new trusted.pki.CertificateCollection();

                recipients.push(cert);
                cipher.recipientsCerts = recipients;

                if (test.encrypt) {
                    assert.doesNotThrow(function () {
                        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/" + fileForTests,
                            //DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.enc",
                            DEFAULT_OUT_PATH + "/" + test.name + ".txt.enc",
                            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
                    }, "Encryption must be sucessfull");
                }
                else {
                    assert.throws(function () {
                        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/" + fileForTests,
                            //DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.enc",
                            DEFAULT_OUT_PATH + "/" + test.name + ".txt.enc",
                            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
                    }, "Encryption must fail");
                }
            });

            it("Decrypt", function () {
                var deCipher = new trusted.pki.Cipher();

                if (test.decrypt) {
                    assert.doesNotThrow(function () {
                        deCipher.decrypt(DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.enc", DEFAULT_OUT_PATH + "/" + test.name + ".txt", trusted.DataFormat.DER);
                    }, "Decryption must be sucessfull");
                }
                else {
                    assert.throws(function () {
                        deCipher.decrypt(DEFAULT_RESOURCES_PATH + "/" + test.name + ".txt.enc", DEFAULT_OUT_PATH + "/" + test.name + ".txt", trusted.DataFormat.DER);
                    }, "Decryption must fail");
                }

                // On Linux comparsion test going to fail due different line endings
                //var src = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + fileForTests);
                //var out = fs.readFileSync(DEFAULT_OUT_PATH + "/" + test.name + ".txt");
                //assert.equal(src.toString() === out.toString(), true, "Source and decrypted files diff");
            });
        });
    });
});

