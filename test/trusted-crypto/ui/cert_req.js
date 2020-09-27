"use strict";

var assert = require("assert");
var trusted = require("../../index.js");
var fs = require("fs");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";
var SUBJECT_NAME = "/C=US/O=Test/CN=example.com";

describe("CertificationRequest 2001", function () {
    var certReq;
    var certReqFromInfo;
    var certReqInfo;
    var publickey;
    var privatekey;
    var ext;
    var exts;
    var oid;
    var reqFile = "CerReq2001.req";
    var cert;


    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });


    it("init", function () {
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


        oid = new trusted.pki.Oid("1.3.6.1.4.1.311.21.7");
        assert.equal(oid !== null, true);

        ext = new trusted.pki.Extension(oid, "1.2.643.2.2.46.0.8");
        assert.equal(ext !== null, true);

        exts.push(ext);
        assert.equal(exts.length, 3);
    });

    it("create", function () {
        var atrs = [
            { type: "C", value: "RU" },
            { type: "CN", value: "Иван Иванов 2001" },
            { type: "L", value: "Yoshkar-Ola" },
            { type: "S", value: "Mari El" },
            { type: "O", value: "Test Org" },
            { type: "1.2.643.100.3", value: "12295279882" },
            { type: "1.2.643.3.131.1.1", value: "002465363366" }
        ];

        certReq.subject = atrs;

        certReq.version = 2;
        assert.equal(typeof (certReq.version), "number", "Bad version value");

        certReq.extensions = exts;
        // assert.equal(typeof (certReq.extensions), "object", "Bad extensions value");

        certReq.exportableFlag = true;
        certReq.pubKeyAlgorithm = "gost2001";
        certReq.containerName = "containerName2001";
    });

    it("save", function () {
        certReq.save(DEFAULT_OUT_PATH + "/" + reqFile, trusted.DataFormat.PEM);
    }).timeout(30000);

    it("delete container", function () {
        trusted.utils.Csp.deleteContainer(certReq.containerName, 75);
    }).timeout(10000);
});

describe("CertificationRequest 2012-256", function () {
    var certReq;
    var certReqFromInfo;
    var certReqInfo;
    var publickey;
    var privatekey;
    var ext;
    var exts;
    var oid;
    var reqFile = "CerReq2012-256.req";


    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });


    it("init", function () {
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


        oid = new trusted.pki.Oid("1.3.6.1.4.1.311.21.7");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "1.2.643.2.2.46.0.8");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 3);
    });

    it("create", function () {
        var atrs = [
            { type: "C", value: "RU" },
            { type: "CN", value: "Иван Иванов 2012-256" },
            { type: "L", value: "Yoshkar-Ola" },
            { type: "S", value: "Mari El" },
            { type: "O", value: "Test Org" },
            { type: "1.2.643.100.3", value: "12295279882" },
            { type: "1.2.643.3.131.1.1", value: "002465363366" }
        ];

        certReq.subject = atrs;
        //assert.equal(typeof (certReq.subject), "string", "Bad subject value");

        certReq.version = 2;
        assert.equal(typeof (certReq.version), "number", "Bad version value");

        //certReq.publicKey = publickey;
        //assert.equal(typeof (certReq.publicKey), "object", "Bad public key value");

        certReq.extensions = exts;
        //assert.equal(typeof (certReq.extensions), "object", "Bad extensions value");

        certReq.exportableFlag = true;
        certReq.pubKeyAlgorithm = "gost2012-256";
        certReq.containerName = "containerName2012_256";
    });

    it("save", function () {
        certReq.save(DEFAULT_OUT_PATH + "/" + reqFile, trusted.DataFormat.PEM);
    }).timeout(30000);

    it("delete container", function () {
        trusted.utils.Csp.deleteContainer(certReq.containerName, 80);
    }).timeout(10000);


});

describe("CertificationRequest 2012-512", function () {
    var certReq;
    var certReqFromInfo;
    var certReqInfo;
    var publickey;
    var privatekey;
    var ext;
    var exts;
    var oid;
    var reqFile = "CerReq2012-512.req";


    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });


    it("init", function () {
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


        oid = new trusted.pki.Oid("1.3.6.1.4.1.311.21.7");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "1.2.643.2.2.46.0.8");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 3);
    });

    it("create", function () {
        var atrs = [
            { type: "C", value: "RU" },
            { type: "CN", value: "Иван Иванов 2012-512" },
            { type: "L", value: "Yoshkar-Ola" },
            { type: "S", value: "Mari El" },
            { type: "O", value: "Test Org" },
            { type: "1.2.643.100.3", value: "12295279882" },
            { type: "1.2.643.3.131.1.1", value: "002465363366" }
        ];

        certReq.subject = atrs;
        //assert.equal(typeof (certReq.subject), "string", "Bad subject value");

        certReq.version = 2;
        assert.equal(typeof (certReq.version), "number", "Bad version value");

        //certReq.publicKey = publickey;
        //assert.equal(typeof (certReq.publicKey), "object", "Bad public key value");

        certReq.extensions = exts;
        //assert.equal(typeof (certReq.extensions), "object", "Bad extensions value");

        certReq.exportableFlag = true;
        certReq.pubKeyAlgorithm = "gost2012-512";
        certReq.containerName = "containerName2012_215";
    });

    it("save", function () {
        certReq.save(DEFAULT_OUT_PATH + "/" + reqFile, trusted.DataFormat.PEM);
    }).timeout(30000);

    it("delete container", function () {
        trusted.utils.Csp.deleteContainer(certReq.containerName, 81);
    }).timeout(10000);

});
