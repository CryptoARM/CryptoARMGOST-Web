"use strict";

var assert = require("assert");
var trusted = require("../../index.js");

var DEFAULT_CERTSTORE_PATH = "test/хранилище";
var DEFAULT_RESOURCES_PATH = "test/исходные";

describe("CSP certificates and containers 2012-256", function () {
    var cert;
    var containerName = "certificate2012-256";

    function checkFile(filePath) {
        try {
            return fs.statSync(filePath).isFile();
        } catch (err) {
            return false;
        }
    }

    before(function () {
        if (checkFile(DEFAULT_CERTSTORE_PATH + "/cash.json")) {
            fs.unlinkSync(DEFAULT_CERTSTORE_PATH + "/cash.json");
        }
    });


    it("import pfx", function () {
        var pkcs12 = new trusted.pki.PKCS12();
        pkcs12.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.pfx");
        trusted.utils.Csp.importPkcs12(pkcs12, "1");
    }).timeout(30000);

    it("install certificate to container", function () {
        cert = new trusted.pki.Certificate();

        cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer");
        trusted.utils.Csp.installCertificateToContainer(cert, containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
    }).timeout(10000);

    it("get certificate from container", function () {
        cert = new trusted.pki.Certificate();

        cert = trusted.utils.Csp.getCertificateFromContainer(containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
        assert.equal(typeof (cert.version), "number", "Bad version value");
    }).timeout(30000);

    it("install certificate from container", function () {

        trusted.utils.Csp.installCertificateFromContainer(containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
    }).timeout(30000);

    it("get container name by certificate", function () {
        cert = new trusted.pki.Certificate();

        cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer");
        containerName = trusted.utils.Csp.getContainerNameByCertificate(cert, "MY");
        assert.equal(containerName.length > 0, true, "Bad container name");
    }).timeout(30000);

    it("Verify certificate chain", function () {
        cert = new trusted.pki.Certificate();
        cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer");

        var res = trusted.utils.Csp.verifyCertificateChain(cert);
        assert.equal(res, true, "No verify");
    }).timeout(10000);


    it("Build certificate chain", function () {
        var certs = new trusted.pki.CertificateCollection();

        cert = new trusted.pki.Certificate();

        cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer");
        certs = trusted.utils.Csp.buildChain(cert);
        assert.equal(certs.length === 2, true, "chain is building");
    }).timeout(30000);

    it("Find certificate in MY store and check that private key exportable", function () {
        var res;
        cert = new trusted.pki.Certificate();
        cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer");
        res = trusted.utils.Csp.isHaveExportablePrivateKey(cert);
        assert.equal(res, true, "No exportable");
    }).timeout(30000);

    it("delete container and certificate", function () {
        var providerSystem = new trusted.pkistore.ProviderCryptopro();
        var store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");

        store.addProvider(providerSystem.handle);


        cert = new trusted.pki.Certificate();
        cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer");
        store.deleteCert(providerSystem.handle, "MY", cert);

        trusted.utils.Csp.deleteContainer(containerName, 80);

    }).timeout(30000);
});

