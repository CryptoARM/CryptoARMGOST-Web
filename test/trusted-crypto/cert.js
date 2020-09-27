"use strict";

var assert = require("assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var trusted = require("../index.js");
var childProcess = require("child_process");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";
var DEFAULT_CERTSTORE_PATH = "test/CertStore";

var compare_app = os.type() === "Windows_NT" ? "fc" : "diff";
var compare_params = os.type() === "Windows_NT" ? "" : "--strip-trailing-cr";

describe("CERTIFICATE 2001", function () {
    var cert;
    var exts;
	var certFile = "TestCrypto2001.cer";
	var certReq;
	var store;
	var providerSystem;

	function checkFile(filePath) {
    try {
        return fs.statSync(filePath).isFile();
    } catch (err) {
        return false;
    }
	}


	before(function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        };

		if (checkFile(DEFAULT_CERTSTORE_PATH + "/cash.json")) {
        fs.unlinkSync(DEFAULT_CERTSTORE_PATH + "/cash.json");
		}
    });

	providerSystem = new trusted.pkistore.ProviderCryptopro();
    store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
    store.addProvider(providerSystem.handle);


    it("init", function() {
        var ext1;
        var ext2;
        var oid;

        cert = new trusted.pki.Certificate();
        assert.equal(cert !== null, true);
    });

    it("load", function () {
        cert.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
    });

    it("import", function () {
        var icert = new trusted.pki.Certificate();
        var data = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + certFile);
        icert.import(data, trusted.DataFormat.PEM);
        assert.equal(typeof (icert.version), "number", "Bad version value");
    });

    it("export PEM", function () {
        var buf = cert.export(trusted.DataFormat.PEM);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
    });

    it("export Default", function () {
        var buf = cert.export();

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("export DER", function () {
        var buf = cert.export(trusted.DataFormat.DER);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("duplicate", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    });

    it("equals", function () {
        var cert1, cert2, cert3;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        cert3 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    });

    it("compare", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), 1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    });

    it("save", function () {
        cert.save(DEFAULT_OUT_PATH + "/out2001.cer", trusted.DataFormat.PEM);

        var cmd = `${compare_app} ${compare_params} ${path.join(DEFAULT_RESOURCES_PATH, certFile)} ${path.join(DEFAULT_OUT_PATH, "/out2001.cer")}`;

        try {
            childProcess.execSync(cmd);
        } catch (err) {
           throw new Error("Resource and out certificate file diff");
        }
    });

    it("params", function () {
        assert.equal(cert.version, 3, "Bad version value");
        assert.equal(typeof (cert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (cert.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
        assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (cert.notAfter), "object", "Bad notAfter value");
        assert.equal(typeof (cert.notBefore), "object", "Bad notBefore value");
        assert.equal(typeof (cert.serialNumber), "string", "Bad serialNumber value");
        assert.equal(typeof (cert.thumbprint), "string", "Bad thumbprint value");
        //assert.equal(typeof (cert.type), "number", "Bad type value");
        assert.equal(typeof (cert.keyUsage), "number", "Bad keyUsage value");
        assert.equal(typeof (cert.signatureAlgorithm), "string", "Bad signatureAlgorithm value");
        assert.equal(typeof (cert.signatureDigestAlgorithm), "string", "Bad signatureDigestAlgorithm value");
        assert.equal(typeof (cert.publicKeyAlgorithm), "string", "Bad publicKeyAlgorithm value");
        assert.equal(typeof (cert.organizationName), "string", "Bad organizationName value");
        assert.equal(typeof (cert.OCSPUrls), "object", "Bad OCSPUrls value");
        assert.equal(cert.OCSPUrls.length, 1, "Bad OCSP urls length");
        assert.equal(typeof (cert.CAIssuersUrls), "object", "Bad CA Issuers value");
        assert.equal(cert.CAIssuersUrls.length, 1, "Bad CA Issuers urls length");
        //assert.equal(cert.extensions.length, 7, "Bad extensions length");
        assert.equal(typeof (cert.isSelfSigned), "boolean", "Error check self signed");
        assert.equal(typeof (cert.isCA), "boolean", "Error check CA");
    });

    it("hash", function () {
        var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);

        var hash1 = cert1.hash();
        var hash2 = cert1.hash("sha1");
        var hash3 = cert1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

	/* it("Check revoked certificate", function () { //требует установки корневого сертификата
        var crl1;

		var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/revoked2001.cer");
		store.addCert(providerSystem.handle, "AddressBook", cert1);

		var cert_ca = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cacert.cer");
		store.addCert(providerSystem.handle, "ROOT", cert_ca);

		crl1 = new trusted.pki.CRL();
		crl1.load(DEFAULT_RESOURCES_PATH + "/crl2001.crl");
		store.addCrl(providerSystem.handle, "CA", crl1);


		var res = trusted.utils.Csp.verifyCertificateChain(cert1);
        assert.equal(res, false, "Is valid");
    }).timeout(30000); */

	it("Check expired qualified certificate", function () {
       	var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/qualified2001.cer");
		store.addCert(providerSystem.handle, "AddressBook", cert1);

		var res = trusted.utils.Csp.verifyCertificateChain(cert1);
        assert.equal(res, false, "Not valid");
    }).timeout(30000);

});

describe("CERTIFICATE 2012-256", function () {
    var cert;
    var exts;
	var certFile = "TestCrypto2012-256.cer";
	var certReq;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        var ext1;
        var ext2;
        var oid;

        cert = new trusted.pki.Certificate();
        assert.equal(cert !== null, true);
    });

    it("load", function () {
        cert.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
    });

    it("import", function () {
        var icert = new trusted.pki.Certificate();
        var data = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + certFile);
        icert.import(data, trusted.DataFormat.PEM);
        assert.equal(typeof (icert.version), "number", "Bad version value");
    });

    it("export PEM", function () {
        var buf = cert.export(trusted.DataFormat.PEM);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
    });

    it("export Default", function () {
        var buf = cert.export();

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("export DER", function () {
        var buf = cert.export(trusted.DataFormat.DER);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("duplicate", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    });

    it("equals", function () {
        var cert1, cert2, cert3;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        cert3 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    });

    it("compare", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), 1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    });

    it("save", function () {
        cert.save(DEFAULT_OUT_PATH + "/out2012_256.cer", trusted.DataFormat.PEM);

        var cmd = `${compare_app} ${compare_params} ${path.join(DEFAULT_RESOURCES_PATH, certFile)} ${path.join(DEFAULT_OUT_PATH, "/out2012_256.cer")}`;

        try {
            childProcess.execSync(cmd);
        } catch (err) {
           throw new Error("Resource and out certificate file diff");
        }
    });

    it("params", function () {
        assert.equal(cert.version, 3, "Bad version value");
        assert.equal(typeof (cert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (cert.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
        assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (cert.notAfter), "object", "Bad notAfter value");
        assert.equal(typeof (cert.notBefore), "object", "Bad notBefore value");
        assert.equal(typeof (cert.serialNumber), "string", "Bad serialNumber value");
        assert.equal(typeof (cert.thumbprint), "string", "Bad thumbprint value");
        //assert.equal(typeof (cert.type), "number", "Bad type value");
        assert.equal(typeof (cert.keyUsage), "number", "Bad keyUsage value");
        assert.equal(typeof (cert.signatureAlgorithm), "string", "Bad signatureAlgorithm value");
        assert.equal(typeof (cert.signatureDigestAlgorithm), "string", "Bad signatureDigestAlgorithm value");
        assert.equal(typeof (cert.publicKeyAlgorithm), "string", "Bad publicKeyAlgorithm value");
        assert.equal(typeof (cert.organizationName), "string", "Bad organizationName value");
        assert.equal(typeof (cert.OCSPUrls), "object", "Bad OCSPUrls value");
        assert.equal(cert.OCSPUrls.length, 1, "Bad OCSP urls length");
        assert.equal(typeof (cert.CAIssuersUrls), "object", "Bad CA Issuers value");
        assert.equal(cert.CAIssuersUrls.length, 1, "Bad CA Issuers urls length");
        //assert.equal(cert.extensions.length, 7, "Bad extensions length");
        assert.equal(typeof (cert.isSelfSigned), "boolean", "Error check self signed");
        assert.equal(typeof (cert.isCA), "boolean", "Error check CA");
    });

    it("ru", function () {
        var ruCert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");

        assert.equal(ruCert.version, 3, "Bad version value");
        assert.equal(typeof (ruCert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (ruCert.subjectName), "string", "Bad subjectName value");
    });



    it("hash", function () {
        var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);

        var hash1 = cert1.hash();
        var hash2 = cert1.hash("sha1");
        var hash3 = cert1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

	/*it("Create selfsigned certificate", function() {


			var ext;
			var exts;
			var oid;
			var selfCert;


			certReq = new trusted.pki.CertificationRequest();
			assert.equal(certReq !== null, true);

			exts = new trusted.pki.ExtensionCollection();
			assert.equal(exts !== null, true);


			oid = new trusted.pki.Oid("keyUsage");
			assert.equal(oid !== null, true);

			ext = new trusted.pki.Extension(oid, "critical,keyAgreement,dataEncipherment,nonRepudiation,digitalSignature");
			assert.equal(ext !== null, true);
			assert.equal(exts.length, 0);

			exts.push(ext);
			assert.equal(exts.length, 1);


			oid = new trusted.pki.Oid("extendedKeyUsage");
			assert.equal(oid !== null, true);

			ext = new trusted.pki.Extension(oid, "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4");
			assert.equal(ext !== null, true);

			exts.push(ext);
			assert.equal(exts.length, 2);

			var atrs = [
				{ type: "C", value: "RU" },
				{ type: "CN", value: "Иван Иванов 2012-256" },
				{ type: "localityName", value: "Yoshkar-Ola" },
				{ type: "stateOrProvinceName", value: "Mari El" },
				{ type: "O", value: "Test Org" },
				{ type: "1.2.643.100.3", value: "12295279882" },
				{ type: "1.2.643.3.131.1.1", value: "002465363366" }
			];

			certReq.subject = atrs;
			certReq.version = 2;
			certReq.extensions = exts;
		   	certReq.exportableFlag = true;
			certReq.pubKeyAlgorithm = "gost2012-256";
			certReq.containerName = "containerName2012-256";

			selfCert = new trusted.pki.Certificate(certReq);
			selfCert.serialNumber = "0CAD16E988B12001";
			selfCert.notAfter = 60 * 60 * 24 * 365; // 365 days in sec
			selfCert.sign();
			selfCert.save(DEFAULT_OUT_PATH + "/out2012_256_self.cer", trusted.DataFormat.PEM);
			}).timeout(30000);

		it("delete container", function() {
			trusted.utils.Csp.deleteContainer(certReq.containerName, 75);
		}).timeout(10000);*/

	it("Check qualified certificate", function () {
       	var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/qual_cert2012.cer");
		//store.addCert(providerSystem.handle, "AddressBook", cert1);

		var res = trusted.utils.Csp.verifyCertificateChain(cert1);
        assert.equal(res, true, "Not valid");
    }).timeout(30000);

});

describe("CERTIFICATE 2012-512", function () {
    var cert;
    var exts;
	var certFile = "TestCrypto2012-512.cer";
	var certReq;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    it("init", function () {
        var ext1;
        var ext2;
        var oid;

        cert = new trusted.pki.Certificate();
        assert.equal(cert !== null, true);
    });

    it("load", function () {
        cert.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
    });

    it("import", function () {
        var icert = new trusted.pki.Certificate();
        var data = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + certFile);
        icert.import(data, trusted.DataFormat.PEM);
        assert.equal(typeof (icert.version), "number", "Bad version value");
    });

    it("export PEM", function () {
        var buf = cert.export(trusted.DataFormat.PEM);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
    });

    it("export Default", function () {
        var buf = cert.export();

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("export DER", function () {
        var buf = cert.export(trusted.DataFormat.DER);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("duplicate", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    });

    it("equals", function () {
        var cert1, cert2, cert3;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        cert3 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    });

    it("compare", function () {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.cer");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), 1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    });

    it("save", function () {
        cert.save(DEFAULT_OUT_PATH + "/out2012_512.cer", trusted.DataFormat.PEM);

        var cmd = `${compare_app} ${compare_params} ${path.join(DEFAULT_RESOURCES_PATH, certFile)} ${path.join(DEFAULT_OUT_PATH, "/out2012_512.cer")}`;

        try {
            childProcess.execSync(cmd);
        } catch (err) {
           throw new Error("Resource and out certificate file diff");
        }
    });

    it("params", function () {
        assert.equal(cert.version, 3, "Bad version value");
        assert.equal(typeof (cert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (cert.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
        assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (cert.notAfter), "object", "Bad notAfter value");
        assert.equal(typeof (cert.notBefore), "object", "Bad notBefore value");
        assert.equal(typeof (cert.serialNumber), "string", "Bad serialNumber value");
        assert.equal(typeof (cert.thumbprint), "string", "Bad thumbprint value");
        //assert.equal(typeof (cert.type), "number", "Bad type value");
        assert.equal(typeof (cert.keyUsage), "number", "Bad keyUsage value");
        assert.equal(typeof (cert.signatureAlgorithm), "string", "Bad signatureAlgorithm value");
        assert.equal(typeof (cert.signatureDigestAlgorithm), "string", "Bad signatureDigestAlgorithm value");
        assert.equal(typeof (cert.publicKeyAlgorithm), "string", "Bad publicKeyAlgorithm value");
        assert.equal(typeof (cert.organizationName), "string", "Bad organizationName value");
        assert.equal(typeof (cert.OCSPUrls), "object", "Bad OCSPUrls value");
        assert.equal(cert.OCSPUrls.length, 1, "Bad OCSP urls length");
        assert.equal(typeof (cert.CAIssuersUrls), "object", "Bad CA Issuers value");
        assert.equal(cert.CAIssuersUrls.length, 1, "Bad CA Issuers urls length");
        //assert.equal(cert.extensions.length, 7, "Bad extensions length");
        assert.equal(typeof (cert.isSelfSigned), "boolean", "Error check self signed");
        assert.equal(typeof (cert.isCA), "boolean", "Error check CA");
    });

    it("hash", function () {
        var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile);

        var hash1 = cert1.hash();
        var hash2 = cert1.hash("sha1");
        var hash3 = cert1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

	/*it("Create selfsigned certificate", function() {

			var certReq;
			var ext;
			var exts;
			var oid;
			var selfCert;


			certReq = new trusted.pki.CertificationRequest();
			assert.equal(certReq !== null, true);

			exts = new trusted.pki.ExtensionCollection();
			assert.equal(exts !== null, true);


			oid = new trusted.pki.Oid("keyUsage");
			assert.equal(oid !== null, true);

			ext = new trusted.pki.Extension(oid, "critical,keyAgreement,dataEncipherment,nonRepudiation,digitalSignature");
			assert.equal(ext !== null, true);
			assert.equal(exts.length, 0);

			exts.push(ext);
			assert.equal(exts.length, 1);


			oid = new trusted.pki.Oid("extendedKeyUsage");
			assert.equal(oid !== null, true);

			ext = new trusted.pki.Extension(oid, "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4");
			assert.equal(ext !== null, true);

			exts.push(ext);
			assert.equal(exts.length, 2);

			var atrs = [
				{ type: "C", value: "RU" },
				{ type: "CN", value: "Иван Иванов 2012-512" },
				{ type: "localityName", value: "Yoshkar-Ola" },
				{ type: "stateOrProvinceName", value: "Mari El" },
				{ type: "O", value: "Test Org" },
				{ type: "1.2.643.100.3", value: "12295279882" },
				{ type: "1.2.643.3.131.1.1", value: "002465363366" }
			];

			certReq.subject = atrs;
			certReq.version = 2;
			certReq.extensions = exts;
		   	certReq.exportableFlag = true;
			certReq.pubKeyAlgorithm = "gost2012-512";
			certReq.containerName = "containerName2012-512";

			selfCert = new trusted.pki.Certificate(certReq);
			selfCert.serialNumber = "0CAD16E988B12001";
			selfCert.notAfter = 60 * 60 * 24 * 365; // 365 days in sec
			selfCert.sign();
			selfCert.save(DEFAULT_OUT_PATH + "/out2012_512_self.cer", trusted.DataFormat.PEM);
			}).timeout(30000);

		it("delete container", function() {
			trusted.utils.Csp.deleteContainer(certReq.containerName, 75);
		}).timeout(10000);*/
});

describe("Negative tests", function () {

	function checkFile(filePath) {
    try {
        return fs.statSync(filePath).isFile();
    } catch (err) {
        return false;
    }
	}


	before(function() {
      if (checkFile(DEFAULT_CERTSTORE_PATH + "/cash.json")) {
        fs.unlinkSync(DEFAULT_CERTSTORE_PATH + "/cash.json");
		}
    });

	var providerSystem = new trusted.pkistore.ProviderCryptopro();
    var store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
    store.addProvider(providerSystem.handle);

	it("Load empty certificate's file", function () {  // тест падает при попытке загрузить пустой файл сертификата
		var cert1;

		assert.throws(function() {
			return cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/empty.cer", trusted.DataFormat.PEM);
		});
    });

	it("Load TXT file instead certificate's file", function () {
		var cert1;

		assert.throws(function() {
			return cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.txt", trusted.DataFormat.PEM);
		});
    });

	it("Load invalid certificate's file", function () {
		var cert1;

		assert.throws(function() {
			return cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/invalid_cert_file.cer", trusted.DataFormat.PEM);
		});
    });

	it("Load no exist certificate's file", function () {  // тест падает при попытке загрузить несуществующий файл сертификата
		var cert1;

		assert.throws(function() {
			return cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/not_exist.cer", trusted.DataFormat.PEM);
		});
    });

	it("Chek certificate invalid signature", function () {
       	var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/invalid_sign.cer");
		store.addCert(providerSystem.handle, "AddressBook", cert1);
		var res = trusted.utils.Csp.verifyCertificateChain(cert1);
		assert.equal(res, false, "Is valid");
    });
});

describe("Additional fields and extensions", function () {
    var cert = null;
    var certFile = "qual_cert2012.cer";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        cert = new trusted.pki.Certificate();
        cert.load(DEFAULT_RESOURCES_PATH + "/" + certFile);
    });

    it("Key Usage string values", function () {
        var ku = cert.keyUsageString;
        assert.strictEqual(typeof (ku), "object", "KU must be array");
        assert.strictEqual(ku.length, 4, "current test certificate KU length");
        ku.forEach(function(curUsage) {
            assert.strictEqual(typeof (curUsage), "string",
                "KU must be array of OID strings");
        });

        const usages = [
            {val: "digitalSignature", result: true},
            {val: "nonRepudiation", result: true},
            {val: "keyEncipherment", result: true},
            {val: "dataEncipherment", result: true},
            {val: "keyAgreement", result: false},
            {val: "keyCertSign", result: false},
            {val: "cRLSign", result: false},
            {val: "encipherOnly", result: false},
            {val: "decipherOnly", result: false}
        ];

        usages.forEach(function(curUsg) {
            assert.strictEqual(ku.includes(curUsg.val), curUsg.result,
                "usage " + curUsg.val + " must" + (curUsg.result?"":" not") + " present");
        });
    });

    it("EKU", function () {
        var eku = cert.enhancedKeyUsage;
        assert.strictEqual(typeof (eku), "object", "EKU must be array");
        assert.strictEqual(eku.length, 6, "current test certificate EKU");
        assert.strictEqual(typeof (eku[0]), "string",
            "EKU must be array of OID strings");

        const expectedEKU = ["1.3.6.1.5.5.7.3.2", "1.2.643.2.2.34.6", "1.3.6.1.5.5.7.3.4",
            "1.2.643.3.185.1", "1.2.643.3.5.10.2.12", "1.2.643.3.7.8.1"];

        expectedEKU.forEach(function(ekuToCheck) {
            assert.strictEqual(eku.includes(ekuToCheck), true,
                ekuToCheck + " must present in EKU");
        });
    });
});

describe("ASYNC CERTIFICATE METHODS", function () {
    var cert;
    var certFile = "TestCrypto2012-256.cer";
    var certReq;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

    });

    it.skip("load", function (done) {
        cert = new trusted.pki.Certificate();
        cert.loadAsync(DEFAULT_RESOURCES_PATH + "/" + certFile, done);
    });

    it.skip("import", function (done) {
        var icert = new trusted.pki.Certificate();
        var data = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + certFile);
        icert.importAsync(data, trusted.DataFormat.PEM, function (msg) {
            if (msg) {
                done(msg);
                return;
            }

            assert.equal(typeof (icert.version), "number",
                "Version field type check failed. Certificate not imported?");
            done();
        });
    });

    it.skip("export PEM", function (done) {
        cert.exportAsync(trusted.DataFormat.PEM, function (err, result) {
            if (err) {
                done(err);
                return;
            }

            var buf = result;
            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
            done();
        });
    });

    it.skip("export DER", function (done) {
        cert.exportAsync(trusted.DataFormat.DER, function (err, result) {
            if (err) {
                done(err);
                return;
            }

            var buf = result;
            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
            done();
        });
    });

    it.skip("save", function (done) {
        cert.saveAsync(DEFAULT_OUT_PATH + "/out2012_256.cer", trusted.DataFormat.PEM, function (msg) {
            if (msg) {
                done(msg);
                return;
            }

            var cmd = `${compare_app} ${compare_params} ${path.join(DEFAULT_RESOURCES_PATH, certFile)} ${path.join(DEFAULT_OUT_PATH, "/out2012_256.cer")}`;

            assert.doesNotThrow(function () {
                childProcess.execSync(cmd);
            }, "Resource and out certificate file diff");

            done();
        });
    });

    it("Check qualified certificate", function (done) {
        var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/qual_cert2012.cer");

        trusted.utils.Csp.verifyCertificateChainAsync(cert1, function (err, result) {
            if (err) {
                done(err);
                return;
            }

            assert.strictEqual(result, true, "Certificate expected to be valid");
            done();
        });
    }).timeout(30000);

});
