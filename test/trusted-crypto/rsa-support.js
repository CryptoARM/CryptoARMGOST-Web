"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("RSA support", function () {
    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    var rsaCertsShaDigests = ["1", "256", "384", "512"];

    rsaCertsShaDigests.forEach(function(digestType) {
        describe("RSA signature support (with sha " + digestType + ")", function () {
            var certFile = digestType + ".cer";
            var cert;
            var sd;
            var signFile = digestType + ".txt.sig";

            it("Load certificate", function () {
                cert = new trusted.pki.Certificate();
                assert.equal(cert !== null, true);
                cert.load(DEFAULT_RESOURCES_PATH + "/RSA/" + certFile, trusted.DataFormat.PEM);
            });

            it("Certificate validity", function () {
                var result = trusted.utils.Csp.verifyCertificateChain(cert);
                assert.strictEqual(result, true, "Not valid");
            });

            it("Sign data", function () {
                sd = new trusted.cms.SignedData();

                //sd.policies = ["detached"];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            });

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + signFile, trusted.DataFormat.PEM);

            });

            it("Verify signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });
        });
    });

    describe("Cipher with RSA", function () {
        var certs;
        var certFile = "RSA/256.cer";

        const encodings = [
            {
                name: "PEM",
                value: trusted.DataFormat.PEM
            },
            {
                name: "DER",
                value: trusted.DataFormat.DER
            },
        ];

        const ciphers = [
            {
                name: "RC2",
                value: trusted.EncryptAlg.RC2
            },
            // not supported?
            // {
            //     name: "RC4",
            //     value: trusted.EncryptAlg.RC4
            // },
            {
                name: "DES",
                value: trusted.EncryptAlg.DES
            },
            {
                name: "3DES",
                value: trusted.EncryptAlg.DES3
            },
            {
                name: "AES 128",
                value: trusted.EncryptAlg.AES_128
            },
            {
                name: "AES 192",
                value: trusted.EncryptAlg.AES_192
            },
            {
                name: "AES 256",
                value: trusted.EncryptAlg.AES_256
            },
        ];


        it("init recipients", function () {
            certs = new trusted.pki.CertificateCollection();
            certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.PEM));
        });

        ciphers.forEach(function(curCipher) {
            describe("Cipher: " + curCipher.name, function () {
                encodings.forEach(function(encoding) {
                    const SOURCE_PATH = DEFAULT_RESOURCES_PATH + "/test.txt";
                    const ENCRYPTED_PATH = DEFAULT_OUT_PATH + "/encAssymRSA-"
                        + curCipher.name + "-" + encoding.name + ".txt.enc";
                    const DECRYPTED_PATH = DEFAULT_OUT_PATH + "/encAssymRSA-"
                        + curCipher.name + "-" + encoding.name + ".txt";

                    it("encrypt with encoding " + encoding.name, function () {
                        var cipher = new trusted.pki.Cipher();
                        cipher.recipientsCerts = certs;
                        cipher.encrypt(
                            SOURCE_PATH,
                            ENCRYPTED_PATH,
                            curCipher.value,
                            encoding.value
                        );
                    });

                    it("decrypt with encoding " + encoding.name, function () {
                        var deCipher = new trusted.pki.Cipher();

                        deCipher.decrypt(
                            ENCRYPTED_PATH,
                            DECRYPTED_PATH,
                            encoding.value
                        );

                        var res = fs.readFileSync(SOURCE_PATH);
                        var out = fs.readFileSync(DECRYPTED_PATH);

                        assert.strictEqual(res.toString(), out.toString(), "Source and decrypted files diff");
                    });
                });
            });
        });
    });
});
