"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var DEFAULT_RESOURCES_PATH = "test/resources";

describe("CSP", function () {
    it("version", function () {
        assert.equal(typeof (trusted.utils.Csp.getCPCSPVersion()), "string", "Bad version value");
    });

    it("version PKZI", function () {
        assert.equal(typeof (trusted.utils.Csp.getCPCSPVersionPKZI()), "string", "Bad version PKZI value");
    });

    it("version SKZI", function () {
        assert.equal(typeof (trusted.utils.Csp.getCPCSPVersionSKZI()), "string", "Bad version SKZI value");
    });

    it("security lvl", function () {
        assert.equal(typeof (trusted.utils.Csp.getCPCSPSecurityLvl()), "string", "Bad security lvl value");
    });

    it("providers", function () {
        var providers = trusted.utils.Csp.enumProviders();
        assert.equal(providers.length > 0, true, "Bad providers count");
    });

    it("license", function () {
        assert.equal(typeof (trusted.utils.Csp.checkCPCSPLicense()), "boolean", "Error check CSP license");
        assert.equal(typeof (trusted.utils.Csp.getCPCSPLicense()), "string", "Error get CSP license");
    });

    it("gost providers", function () {
        assert.equal(typeof (trusted.utils.Csp.isGost2001CSPAvailable()), "boolean", "Error check provider 75 (GOST 2001)");
        assert.equal(typeof (trusted.utils.Csp.isGost2012_256CSPAvailable()), "boolean", "Error check provider 80 (GOST 2012 256)");
        assert.equal(typeof (trusted.utils.Csp.isGost2012_512CSPAvailable()), "boolean", "Error check provider 81 (GOST 2012 512)");
    });

    it("containers", function () {
        var containers = trusted.utils.Csp.enumContainers(75);
        assert.equal(containers.length > 0, true, "Bad containers count");
    }).timeout(10000);

});

/*
describe("CSP certificates and containers 2012-256", function() {
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


	it("import pfx", function() {
        var pkcs12 = new trusted.pki.PKCS12();
		pkcs12.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.pfx");
		trusted.utils.Csp.importPkcs12(pkcs12, "1");
    }).timeout(10000);

	it ("install certificate to container", function() {
		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer" );
		trusted.utils.Csp.installCertificateToContainer(cert, containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
	});

	it ("get certificate from container", function() {
		cert = new trusted.pki.Certificate();

		cert = trusted.utils.Csp.getCertificateFromContainer(containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
		assert.equal( typeof (cert.version), "number", "Bad version value" );
	});

	it ("install certificate from container", function() {

		trusted.utils.Csp.installCertificateFromContainer(containerName, 80, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider");
	}).timeout(10000);

	it ("get container name by certificate", function() {
		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer" );
		containerName = trusted.utils.Csp.getContainerNameByCertificate(cert, "MY");
		assert.equal( containerName.length > 0, true, "Bad container name" );
	}).timeout(10000);

	it ("Verify certificate chain", function() {
		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer" );
		var res = trusted.utils.Csp.verifyCertificateChain(cert);
		assert.equal(res, true, "No verify");
		});


	it ("Build certificate chain", function() {
		var certs = new trusted.pki.CertificateCollection();

		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer" );
		certs = trusted.utils.Csp.buildChain(cert);
		assert.equal(certs.length === 2, true, "chain is building");
	}).timeout(30000);

	it ("Find certificate in MY store and check that private key exportable", function() {
		var res;
		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer" );
		res = trusted.utils.Csp.isHaveExportablePrivateKey(cert);
		assert.equal(res, true, "No exportable");
	});

	it("delete container and certificate", function() {
		var providerSystem = new trusted.pkistore.ProviderCryptopro();
		var store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");

		store.addProvider(providerSystem.handle);


		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-256.cer" );
		store.deleteCert(providerSystem.handle, "MY", cert);

		trusted.utils.Csp.deleteContainer(containerName, 80);

	}).timeout(10000);
});

describe("CSP certificates and containers 2012-512", function() {
	var cert;
	var containerName = "certificate2012-512";

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


	it("import pfx", function() {
        var pkcs12 = new trusted.pki.PKCS12();
		pkcs12.load(DEFAULT_RESOURCES_PATH + "/certificate2012-512.pfx");
		trusted.utils.Csp.importPkcs12(pkcs12, "1");
    }).timeout(10000);

	it ("install certificate to container", function() {
		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-512.cer" );
		trusted.utils.Csp.installCertificateToContainer(cert, containerName, 81, "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider");
	});

	it ("get certificate from container", function() {
		cert = new trusted.pki.Certificate();

		cert = trusted.utils.Csp.getCertificateFromContainer(containerName, 81, "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider");
		assert.equal( typeof (cert.version), "number", "Bad version value" );
	});

	it ("install certificate from container", function() {

		trusted.utils.Csp.installCertificateFromContainer(containerName, 81, "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider");
	}).timeout(10000);

	it ("get container name by certificate", function() {
		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-512.cer" );
		containerName = trusted.utils.Csp.getContainerNameByCertificate(cert, "MY");
		assert.equal( containerName.length > 0, true, "Bad container name" );
	}).timeout(10000);

	it ("Verify certificate chain", function() {
		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-512.cer" );
		var res = trusted.utils.Csp.verifyCertificateChain(cert);
		assert.equal(res, true, "No verify");
		});


	it ("Build certificate chain", function() {
		var certs = new trusted.pki.CertificateCollection();

		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-512.cer" );
		certs = trusted.utils.Csp.buildChain(cert);
		assert.equal(certs.length === 2, true, "chain is building");
	}).timeout(30000);

	it ("Find certificate in MY store and check that private key exportable", function() {
		var res;
		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-512.cer" );
		res = trusted.utils.Csp.isHaveExportablePrivateKey(cert);
		assert.equal(res, true, "No exportable");
	});

	it("delete container and certificate", function() {
		var providerSystem = new trusted.pkistore.ProviderCryptopro();
		var store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");

		store.addProvider(providerSystem.handle);


		cert = new trusted.pki.Certificate();
		cert.load(DEFAULT_RESOURCES_PATH + "/certificate2012-512.cer" );
		store.deleteCert(providerSystem.handle, "MY", cert);

		trusted.utils.Csp.deleteContainer(containerName, 81);

	}).timeout(10000);
});	*/

/*describe("Check revoked certificate 2012", function() {
	var cert, rootCA;
	var crl;
	var providerSystem, store;

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
	
	after(function () {
		store.deleteCert(providerSystem.handle, "ADDRESSBOOK", cert);
       store.deleteCrl(providerSystem.handle, "CA", crl);
	});
	
	it("init", function () {
        providerSystem = new trusted.pkistore.ProviderCryptopro();
        
        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
       
        store.addProvider(providerSystem.handle);
    
       	cert = new trusted.pki.Certificate();
		rootCA = new trusted.pki.Certificate();
        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/revoked2012.cer", trusted.DataFormat.PEM);
		rootCA = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cacert2012.cer", trusted.DataFormat.PEM);
        
		

        store.addCert(providerSystem.handle, "ADDRESSBOOK", cert);
		store.addCert(providerSystem.handle, "ROOT", rootCA);
    }).timeout(10000);
	
	it ("Verify revoked certificate 2012", function() {
		crl = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");
		store.addCrl(providerSystem.handle, "CA", crl);
		var res = trusted.utils.Csp.verifyCertificateChain(cert);
		assert.equal(res, false, "No verify");
	});
	
	it ("Verify certificate 2012 by crl", function() {
		crl = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl_empty.crl");
		store.addCrl(providerSystem.handle, "CA", crl);
		var res = trusted.utils.Csp.verifyCertificateChain(cert);
		assert.equal(res, true, "No verify");
	});
});*/

describe("ASYNC CSP METHODS", function () {
    var cert;
    var certFile = "TestCrypto2012-256.cer";

	it ("Build certificate chain", function(done) {
		cert = new trusted.pki.Certificate();

		cert.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
		trusted.utils.Csp.buildChainAsync(cert, function (error, certs) {
			if (error) {
				done(error);
			}

			assert.equal(certs.length > 0, true, "Chain must not be empty");
			done();
		});
	}).timeout(30000);
});
