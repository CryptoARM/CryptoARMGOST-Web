"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

var isSupportGost2015 = () => {
    const cspVersion = trusted.utils.Csp.getCPCSPVersion();
    const versionPKZI = trusted.utils.Csp.getCPCSPVersionPKZI();

    if (cspVersion && versionPKZI
        && parseInt((cspVersion.charAt(0)), 10) === 5 && parseInt((versionPKZI), 10) >= 11635) {
        return true;
    } else {
        return false;
    }
}

var gost2015Enabled;

describe("Cipher 2001", function () {
    var cipher;
    var certFile = "TrustedCrypto2001.cer";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        gost2015Enabled = isSupportGost2015();
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
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2001.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.PEM);
    });

    it("encrypt DER", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2001_der.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
    });

    it("decrypt PEM", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym2001.txt.enc", DEFAULT_OUT_PATH + "/decAssym2001.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2001.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt DER", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym2001_der.txt.enc", DEFAULT_OUT_PATH + "/decAssym2001_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2001_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });
});

describe("Cipher 2012-256", function () {
    var cipher;
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

    it("encrypt GOST_28147 PEM", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-GOST_28147.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_28147 DER", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-GOST_28147_der.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
    });

    it("encrypt GOST_R3412_2015_M PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_M.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_M, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_R3412_2015_M DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_M_der.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_M, trusted.DataFormat.DER);
    });

    it("encrypt GOST_R3412_2015_K PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_K.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_K, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_R3412_2015_K DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_K_der.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_K, trusted.DataFormat.DER);
    });

    it("decrypt GOST_28147 PEM", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-GOST_28147.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-GOST_28147.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-GOST_28147.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_28147 DER", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-GOST_28147_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-GOST_28147_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-GOST_28147_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_M PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_M.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_M.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_M.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_M DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_M_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_M_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_M_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_K PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_K.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_K.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_K.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_K DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-256-R3412_2015_K_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_K_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-256-R3412_2015_K_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });
});

describe("Cipher 2012-512", function () {
    var cipher;
    var certFile = "TrustedCrypto2012-512.cer";

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

    it("encrypt GOST_28147 PEM", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-GOST_28147.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_28147 DER", function () {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-GOST_28147_der.txt.enc",
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
    });

    it("encrypt GOST_R3412_2015_M PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_M.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_M, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_R3412_2015_M DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_M_der.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_M, trusted.DataFormat.DER);
    });

    it("encrypt GOST_R3412_2015_K PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_K.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_K, trusted.DataFormat.PEM);
    });

    it("encrypt GOST_R3412_2015_K DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_K_der.txt.enc",
            trusted.EncryptAlg.GOST_R3412_2015_K, trusted.DataFormat.DER);
    });


    it("decrypt GOST_28147 PEM", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-GOST_28147.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-GOST_28147.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-GOST_28147.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_28147 DER", function () {
        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-GOST_28147_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-GOST_28147_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-GOST_28147_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_M PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_M.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_M.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_M.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_M DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_M_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_M_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_M_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_K PEM", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_K.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_K.txt", trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_K.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    it("decrypt GOST_R3412_2015_K DER", function () {
        if (!gost2015Enabled) {
            this.skip();
        }

        cipher = new trusted.pki.Cipher();

        cipher.decrypt(
            DEFAULT_OUT_PATH + "/encAssym2012-512-R3412_2015_K_der.txt.enc",
            DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_K_der.txt", trusted.DataFormat.DER);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym2012-512-R3412_2015_K_der.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });
});

describe("Cipher and deciper \"round\" sized files", function () {
    var certFile = "KU/KU-digitalSignature-keyEncipherment.cer";
    const file_size_list = ["65535", "65536", "65537", "131072"];

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    file_size_list.forEach(function (fileSize) {
        describe("Test for file with size " + fileSize, function () {
            var in_file = DEFAULT_RESOURCES_PATH + "/" + fileSize + ".txt";
            var enc_file = DEFAULT_OUT_PATH + "/" + fileSize + ".txt.enc"
            var dec_file = DEFAULT_OUT_PATH + "/" + fileSize + ".txt.dec"

            it("Encrypt DER", function () {
                var cipher = new trusted.pki.Cipher();

                var certs = new trusted.pki.CertificateCollection();
                certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.PEM));
                cipher.recipientsCerts = certs;

                assert.doesNotThrow(function () {
                    cipher.encrypt(in_file, enc_file, trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
                }, "Encryption error");
            });

            it("Decrypt DER", function () {
                var cipher = new trusted.pki.Cipher();

                assert.doesNotThrow(function () {
                    cipher.decrypt(enc_file, dec_file, trusted.DataFormat.DER);
                }, "Error on decryption");

                var res = fs.readFileSync(in_file);
                var out = fs.readFileSync(dec_file);

                assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
            });
        });
    });
});

describe("CIPHER ASYNC", function () {
    var cipher;
    var certFile = "TrustedCrypto2012-256.cer";
    var srcFile = DEFAULT_RESOURCES_PATH + "/test.txt";
    var resPem = DEFAULT_OUT_PATH + "/enc-async-pem.txt";
    var resDer = DEFAULT_OUT_PATH + "/enc-async-der.txt";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        cipher = new trusted.pki.Cipher();
        var certs = new trusted.pki.CertificateCollection();
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER));
        cipher.recipientsCerts = certs;
    });

    it("Async encrypt PEM", function (done) {
        cipher.encryptAsync(srcFile, resPem + ".enc", done,
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.PEM);
    });

    it("Async encrypt DER", function (done) {
        cipher.encryptAsync(srcFile, resDer + ".enc", done,
            trusted.EncryptAlg.GOST_28147, trusted.DataFormat.DER);
    });

    it("Async decrypt PEM", function (done) {
        cipher = new trusted.pki.Cipher();

        cipher.decryptAsync(resPem + ".enc", resPem, function (msg) {
            if (msg) {
                done(msg);
                return;
            }

            var res = fs.readFileSync(srcFile);
            var out = fs.readFileSync(resPem);

            assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
            done();
        }, trusted.DataFormat.PEM);
    });

    it("Async decrypt DER", function (done) {
        cipher = new trusted.pki.Cipher();

        cipher.decryptAsync(resDer + ".enc", resDer, function (msg) {
            if (msg) {
                done(msg);
                return;
            }

            var res = fs.readFileSync(srcFile);
            var out = fs.readFileSync(resDer);

            assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
            done();
        }, trusted.DataFormat.DER);
    });
});

