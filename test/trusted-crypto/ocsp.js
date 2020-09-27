"use strict";

var assert = require("assert");
var trusted = require("../index.js");
var fs = require("fs");

var DEFAULT_RESOURCES_PATH = "test/resources";
var cert2012File = "qual_cert2012.cer"
var cert2001Expired = "TestCrypto2001.cer"
var certRevoked = "certificate_ocsp_revoked.cer"

describe("OCSP", function () {
    var ocsp;
    var ocspImported;
    var ocspDamaged;
    var ocspRevoked;

    var certToCheck;
    var respCerts;
    var respCerts2;

    var cadesEnabled;

    before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
    });

    it("Sending request", function () {
        if (!cadesEnabled)
            this.skip();

        certToCheck = new trusted.pki.Certificate();
        certToCheck.load(DEFAULT_RESOURCES_PATH + "/" + cert2012File)

        var connSettings = new trusted.utils.ConnectionSettings();

        ocsp = new trusted.pki.OCSP(certToCheck, connSettings);
        assert.equal(ocsp !== null, true);
    });

    it("Exporting recieved value", function () {
        if (!cadesEnabled)
            this.skip();

        var ocspRespValue = ocsp.Export();
        assert.equal(Buffer.isBuffer(ocspRespValue), true);
        assert.equal(ocspRespValue.length > 0, true);

        //fs.writeFileSync(DEFAULT_RESOURCES_PATH + "/" + cert2012File + ".ocsp", ocspRespValue);
    });

    it("Importing response data", function () {
        if (!cadesEnabled)
            this.skip();

        var dataToImport = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/damaged.ocsp");
        ocspImported = new trusted.pki.OCSP(dataToImport);

        assert.equal(typeof (ocspImported), "object", "Bad import result value type");
    });

    it("Importing response data for revoked certificate", function () {
        if (!cadesEnabled)
            this.skip();

        var dataToImport = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/revoked.ocsp");
        ocspRevoked = new trusted.pki.OCSP(dataToImport);

        assert.equal(typeof (ocspRevoked), "object", "Bad import result value type");
    });

    it("Verify", function () {
        if (!cadesEnabled)
            this.skip();

        var verifyResult = ocsp.Verify();

        assert.equal(typeof (verifyResult), "number", "Bad result value type");
        assert.equal(verifyResult, 0);
    });

    it("Verify request with bad signature", function () {
        if (!cadesEnabled)
            this.skip();

        var dataDamaged = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + "damaged.ocsp");
        ocspDamaged = new trusted.pki.OCSP(dataDamaged);

        var damagedVerifyResult = ocspDamaged.Verify();

        assert.equal(typeof (damagedVerifyResult), "number", "Bad result value type for damaged resp");
        assert.notEqual(damagedVerifyResult, 0);
    });

    it("OCSP service certificate", function () {
        if (!cadesEnabled)
            this.skip();

        var ocspCert = ocsp.OcspCert;

        assert.equal(typeof (ocspCert), "object", "Expecting certificate is found");
    });

    it("OCSP service certificate method", function () {
        if (!cadesEnabled)
            this.skip();

        var ocspCert = ocsp.getOcspCert();

        assert.equal(typeof (ocspCert), "object", "Expecting certificate is found");
    });

    it("Certificates from response", function () {
        if (!cadesEnabled)
            this.skip();

        respCerts = ocsp.Certificates;

        assert.equal(typeof (respCerts), "object", "Expecting CertificateCollection - object (ocsp)");

        respCerts2 = ocspImported.Certificates;

        assert.equal(typeof (respCerts2), "object", "Expecting CertificateCollection - object (ocsp imported)");
        assert.equal(respCerts2.length, 1, "Expecting not empty collection");
    });

    it("Certificate verify", function () {
        if (!cadesEnabled)
            this.skip();

        var certVerifyStatus = ocsp.VerifyCertificate(respCerts.items(0));

        assert.equal(typeof (certVerifyStatus), "number", "Expecting verify result - number (ocsp)");
        assert.equal(certVerifyStatus, 0, "Verify status must be 0 (good) (1)");

        certVerifyStatus = ocspImported.VerifyCertificate(respCerts2.items(0));

        assert.equal(typeof (certVerifyStatus), "number", "Expecting verify result - number (ocspImported)");
        assert.equal(certVerifyStatus, 0, "Verify status must be 0 (good) (2)");
    });

    it("RespStatus", function () {
        if (!cadesEnabled)
            this.skip();

        var respStatus = ocsp.RespStatus;
        assert.equal(typeof (respStatus), "number", "Bad result value type");
        assert.equal(respStatus, trusted.pki.CPRespStatus.successful);
    });

    it("SignatureAlgorithmOid", function () {
        if (!cadesEnabled)
            this.skip();

        var sigAlgOid = ocsp.SignatureAlgorithmOid;

        assert.equal(typeof (sigAlgOid), "string", "Bad result value type");
        assert.equal(sigAlgOid, "1.2.643.7.1.1.3.2");
    });

    it("SignatureAlgorithmOid for GOST 2001", function () {
        if (!cadesEnabled)
            this.skip();

        var cert2001Exp = new trusted.pki.Certificate();
        cert2001Exp.load(DEFAULT_RESOURCES_PATH + "/" + cert2001Expired)

        var ocsp2001Exp = new trusted.pki.OCSP(cert2001Exp);
        var sigAlgOid = ocsp2001Exp.SignatureAlgorithmOid;

        assert.equal(typeof (sigAlgOid), "string", "Bad result value type");
        assert.equal(sigAlgOid, "1.2.643.2.2.3");
    });

    it("ProducedAt", function () {
        if (!cadesEnabled)
            this.skip();

        var producedAt = ocspImported.ProducedAt;

        assert.equal(typeof (producedAt), "object", "Bad result value type");
        var dateToCompare = new Date("2019-10-24T07:23:53Z");
        assert.equal(producedAt.getTime(), dateToCompare.getTime());
    });

    it("RespNumber", function () {
        if (!cadesEnabled)
            this.skip();

        var respNumber = ocsp.RespNumber;

        assert.equal(typeof (respNumber), "number", "Bad result value type");
        assert.equal(respNumber, 1);
    });

    it("RespIndexByCert", function () {
        if (!cadesEnabled)
            this.skip();

        var respIdx = ocsp.RespIndexByCert(certToCheck);

        assert.equal(typeof (respIdx), "number", "Bad result value type");
        assert.equal(respIdx, 0);
    });

    it("Status of certificate", function () {
        if (!cadesEnabled)
            this.skip();

        var certStatus = ocspImported.Status(0);

        assert.equal(typeof (certStatus), "number", "Bad result value type");
        assert.equal(certStatus, trusted.pki.CPCertStatus.Good);
    });

    it("Status of certificate by default index", function () {
        if (!cadesEnabled)
            this.skip();

        var certStatus = ocspImported.Status();

        assert.equal(typeof (certStatus), "number", "Bad result value type");
        assert.equal(certStatus, trusted.pki.CPCertStatus.Good);
    });

    it("Status of certificate", function () {
        if (!cadesEnabled)
            this.skip();

        var certStatus = ocspRevoked.Status(0);

        assert.equal(typeof (certStatus), "number", "Bad result value type");
        assert.equal(certStatus, trusted.pki.CPCertStatus.Revoked);
    });

    it("RevTime", function () {
        if (!cadesEnabled)
            this.skip();

        var revTime = ocspRevoked.RevTime(0);

        assert.equal(typeof (revTime), "object", "Bad result value type");
        var dateToCompare = new Date("2019-10-28T09:27:20Z");
        assert.equal(revTime.getTime(), dateToCompare.getTime());
    });

    it("RevTime by default index", function () {
        if (!cadesEnabled)
            this.skip();

        var revTime = ocspRevoked.RevTime();

        assert.equal(typeof (revTime), "object", "Bad result value type");
        var dateToCompare = new Date("2019-10-28T09:27:20Z");
        assert.equal(revTime.getTime(), dateToCompare.getTime());
    });

    it("RevReason", function () {
        if (!cadesEnabled)
            this.skip();

        var revReason = ocspRevoked.RevReason(0);

        assert.equal(typeof (revReason), "number", "Bad result value type");
        assert.equal(revReason, trusted.pki.CPCrlReason.CRLREASON_SUPERSEDED);
    });

    it("RevReason by default index", function () {
        if (!cadesEnabled)
            this.skip();

        var revReason = ocspRevoked.RevReason(0);

        assert.equal(typeof (revReason), "number", "Bad result value type");
        assert.equal(revReason, trusted.pki.CPCrlReason.CRLREASON_SUPERSEDED);
    });

    it("ThisUpdate", function () {
        if (!cadesEnabled)
            this.skip();

        var thisUpdate = ocspImported.ThisUpdate(0);

        assert.equal(typeof (thisUpdate), "object", "Bad result value type");
        var dateToCompare = new Date("2019-10-24T07:23:53Z");
        assert.equal(thisUpdate.getTime(), dateToCompare.getTime());
    });

    it("ThisUpdate by default index", function () {
        if (!cadesEnabled)
            this.skip();

        var thisUpdate = ocspImported.ThisUpdate();

        assert.equal(typeof (thisUpdate), "object", "Bad result value type");
        var dateToCompare = new Date("2019-10-24T07:23:53Z");
        assert.equal(thisUpdate.getTime(), dateToCompare.getTime());
    });

    it("NextUpdate", function () {
        if (!cadesEnabled)
            this.skip();

        var nextUpdate = ocspImported.NextUpdate(0);

        assert.equal(typeof (nextUpdate), "object", "Bad result value type");
        assert.equal(nextUpdate.getTime(), 0, "Date with 0 milliseconds value when next update field is absent in response");
    });

    it("NextUpdate by default index", function () {
        if (!cadesEnabled)
            this.skip();

        var nextUpdate = ocspImported.NextUpdate();

        assert.equal(typeof (nextUpdate), "object", "Bad result value type");
        assert.equal(nextUpdate.getTime(), 0, "Date with 0 milliseconds value when next update field is absent in response");
    });
});

