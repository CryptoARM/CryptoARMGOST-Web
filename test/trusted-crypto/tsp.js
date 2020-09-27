"use strict";

var assert = require("assert");
var trusted = require("../index.js");
var fs = require("fs");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("TSP 2012", function () {
    var tspReq94; // Request with GOST 34.11-94 hash alg
    var tspReq;
	var cadesEnabled;
	
    //---TSPRequest----------------------------------
    before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
		if (!cadesEnabled)
            this.skip();
    });
	
    it("TSPRequest - Creating object", function () {
        	
		tspReq = new trusted.pki.TSPRequest("1.2.643.7.1.1.2.2");
       	assert.notEqual(tspReq, null, "Object for gost2012 not created");
    });

	it("TSPRequest - Creating object with error hash algorithm OID", function () {
		var tspReq_err;
		assert.throws(function() {
		return tspReq_err = new trusted.pki.TSPRequest("1.2.643.7.1.1.3.2");
        });
    });
	
    it("TSPRequest - Request certificate flag", function () {
        assert.equal(tspReq.CertReq, true, "Wrong default value for CertReq");

        tspReq.CertReq = true;
        assert.equal(tspReq.CertReq, true, "Wrong value for CertReq");
    });

    it("TSPRequest - Request Nonce flag", function () {
        tspReq.Nonce = false;
        assert.equal(tspReq.Nonce, false, "Wrong value for Nonce");
		
		tspReq.Nonce = true;
		assert.equal(tspReq.Nonce, true, "Wrong default value for Nonce");
    });

    it("TSPRequest - Policy ID", function () {
        assert.equal(tspReq.PolicyId, "", "Wrong default value for PolicyID");
		
		tspReq.PolicyID = "1.2.3.4.5.6.7.8";
		assert.equal(tspReq.PolicyID, "1.2.3.4.5.6.7.8", "Wrong value for PolicyID");
    });

    it("TSPRequest - Hash Algorithm OID", function () {
        assert.equal(tspReq.HashAlgOid, "1.2.643.7.1.1.2.2", "Wrong value for HashAlgOid");
    });

    it("TSPRequest - Add data", function () {
        assert.doesNotThrow(() => {
            var dataBuf = Buffer.from("Test 01");
            tspReq.AddData(dataBuf);
        });
    });

    it("TSPRequest - Data hash value", function () {
		assert.equal(tspReq.DataHash.toString("hex"), "b41478b6e77a0e114dd51892c19ba58fbaadb3ca776856d5aca5132beda98288", "Wrong GOST 2012 hash value");
    });

    //---TSP-----------------------------------------
    var tsp;
    var tsp94; // Response with GOST 34.11-94 hash alg
    var tspImported;
    var failedStamp;

    var serviceCert;
    var serviceCert94;

    it("Sending request", function () {
        var connSettings = new trusted.utils.ConnectionSettings();

        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
	   
        tsp = new trusted.pki.TSP(tspReq, connSettings);
        assert.notEqual(tsp, null, "Response is empty");
    });

	it("Exporting recieved values", function () {
        var tspRespValue = tsp.Export();
        assert.equal(Buffer.isBuffer(tspRespValue), true);
        assert.equal(tspRespValue.length > 0, true);
    });

    it("Importing timestamp data", function () {
        var dataToImport = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/timestamp.der");
        tspImported = new trusted.pki.TSP(dataToImport);

        assert.equal(typeof (tspImported), "object", "Bad import result value type");
    });

    it("Verify", function () {
        var verifyResult = tsp.Verify();

        assert.equal(typeof (verifyResult), "number", "Bad result value type");
        assert.equal(verifyResult, 0, "Good verify result expected (tsp)");
		
		verifyResult = tspImported.Verify();

        assert.equal(typeof (verifyResult), "number", "Bad result value type");
        assert.equal(verifyResult, 0, "Good verify result expected (tspImported)");
    });

    it("Verify stamp with bad signature", function () {
        var dataDamaged = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/" + "damaged.tsp");
        var tspDamaged = new trusted.pki.TSP(dataDamaged);

        var damagedVerifyResult = tspDamaged.Verify();

        assert.equal(typeof (damagedVerifyResult), "number", "Bad result value type for damaged resp");
        assert.notEqual(damagedVerifyResult, 0, "Bad verify result expected");
    });

    it("Certificates from time stamp", function () {
        var stampCerts = tsp.Certificates;

        assert.equal(typeof (stampCerts), "object", "Expecting CertificateCollection - object (tsp)");

        var stampCerts2 = tspImported.Certificates;

        assert.equal(typeof (stampCerts2), "object", "Expecting CertificateCollection - object (tsp94)");
        assert.equal(stampCerts2.length, 1, "Expecting not empty collection");
    });

    it("TSA certificate", function () {
        serviceCert = tsp.TSACertificate;

        assert.equal(typeof (serviceCert), "object", "Expecting Certificate - object (tsp)");
        assert.equal(serviceCert.subjectFriendlyName, 'ООО "КРИПТО-ПРО"', "Unexpected subject name for GOST 2012 authority");
    });

    it("Certificate verify", function () {
        var certVerifyStatus = tsp.VerifyCertificate(serviceCert);

        assert.equal(typeof (certVerifyStatus), "number", "Expecting verify result - number (tsp)");
        assert.equal(certVerifyStatus, 0, "Verify status must be 0 (good) for GOST 2012 authority");
    });

    it("Fail info", function () {
        var failInfo = tsp.FailInfo;

        assert.equal(typeof (failInfo), "number", "Expecting fail code - number (tsp)");
        assert.equal(failInfo, 0, "Fail info must be 0 (good) for GOST 2012 authority");
	});

    it("Failing with unsupported hash alg", function () {
        var tspReqToFail = new trusted.pki.TSPRequest("1.2.643.2.2.9");
        var connSett = new trusted.utils.ConnectionSettings();
        connSett.Address = "http://ocsp.ucparma.ru/tsp/tsp.srf";

        tspReqToFail.AddData(
            Buffer.from("Test 02")
            );

        failedStamp = new trusted.pki.TSP(tspReqToFail, connSett);

        var failInfo = failedStamp.FailInfo;
        assert.equal(typeof (failInfo), "number", "Expecting fail code - number (failedStamp)");
        assert.equal(failInfo, 1, "Fail info must be 1 (bit for unsupported hash alg) for GOST 34.11-94 authority");
    });

    it("Status", function () {
        var status = tsp.Status;
        assert.equal(typeof (status), "number", "Expecting status code - number (tsp)");
        assert.equal(status, 0, "Stamp status must be 0 (good) for GOST 2012 authority");
	});

    it("Status with error", function () {	
		var status = failedStamp.Status;
		assert.equal(typeof (status), "number", "Expecting status code - number");
        assert.equal(status, 2, "Stamp status must be 1 (bit for unsupported hash alg) for sending GOST 34.11-2012 to GOST 34.11-94 authority");
    });

    it("StatusString", function () {
        var statusString = tsp.StatusString;
        assert.equal(typeof (statusString), "string", "Expecting string with description (tsp)");
        assert.equal(statusString, "", "Description string must be empty (good) for GOST 2012 authority");
	});

    it("StatusString 2", function () {
        var statusString = failedStamp.StatusString;
        assert.equal(typeof (statusString), "string", "Expecting string with description (failedStamp)");
        assert.equal(statusString, "", "Description string must not be empty for GOST 34.11-94 authority");
    });

    it("DataHashAlgOID", function () {
        var dataHashAlgOID = tsp.DataHashAlgOID;
        assert.equal(typeof (dataHashAlgOID), "string", "Expecting string with OID (tsp)");
    });

    it("Time stamp - Data hash value", function () {
        assert.equal(typeof (tsp.DataHash), "object", "Expecting buffer with data - object");
        assert.equal(tsp.DataHash.toString("hex"), "b41478b6e77a0e114dd51892c19ba58fbaadb3ca776856d5aca5132beda98288", "Wrong GOST 2012 hash value");
     });

    it("PolicyID", function () {
        var policyID = tsp.PolicyID;
        assert.equal(typeof (policyID), "string", "Expecting string with OID (tsp)");
    });

    it("SerialNumber", function () {
        var serialNumber = tspImported.SerialNumber;
        assert.equal(typeof (serialNumber), "object", "Expecting buffer with data - object");
        assert.equal(serialNumber.toString("hex"), "0417b646a20000000006769eae", "Wrong serial number value");
    });

    it("Time", function () {
        var timeValue = tspImported.Time;
        assert.equal(typeof (timeValue), "object", "Expecting string with time");
        var dateToCompare = new Date("2019-10-31T13:37:53Z");
        assert.equal(timeValue.getTime(), dateToCompare.getTime(), "Wrong time value");
    });

    it("Accuracy", function () {
        var accuracy = tsp.Accuracy;
        assert.equal(typeof (accuracy), "number", "Expecting number of milliseconds (tsp)");
        assert.equal(accuracy, -1, "Wrong accuracy for GOST 2012 authority");
   });

    it("Ordering", function () {
        var ordering = tsp.Ordering;
        assert.equal(typeof (ordering), "boolean", "Expecting boolean flag (tsp)");
        assert.equal(ordering, false, "Wrong ordering for GOST 2012 authority");
   });

    it("HasNonce", function () {
        var hasNonce = tsp.HasNonce;
        assert.equal(typeof (hasNonce), "boolean", "Expecting boolean flag (tsp)");
        assert.equal(hasNonce, true, "Wrong hasNonce for GOST 2012 authority");
  });

    it("TsaName", function () {
        var tsaName = tsp.TsaName;
        assert.equal(typeof (tsaName), "string", "Expecting string with name (tsp)");
        assert.equal(tsaName, "", "Wrong TsaName for GOST 2012 authority");
    });

    it("TsaNameBlob", function () {
        assert.equal(typeof (tsp.TsaNameBlob), "object", "Expecting buffer with data - object");
        assert.equal(tsp.TsaNameBlob.toString("hex"), "", "Wrong GOST 2012 hash value");
    });
});

describe("TSP 2001", function () {
    var tspReq94; // Request with GOST 34.11-94 hash alg
    var cadesEnabled;
	
	before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
		if (!cadesEnabled)
            this.skip();
    });

    //---TSPRequest----------------------------------

    it("TSPRequest - Creating object", function () {
        tspReq94 = new trusted.pki.TSPRequest("1.2.643.2.2.9");

		assert.notEqual(tspReq94, null, "Object for gost2001 not created");
    });


    it("TSPRequest - Request certificate flag", function () {
		
		tspReq94.CertReq = false;
        assert.equal(tspReq94.CertReq, false, "Wrong value for CertReq");

        tspReq94.CertReq = true;
        assert.equal(tspReq94.CertReq, true, "Wrong value for CertReq");
    });

    it("TSPRequest - Request Nonce flag", function () {
        tspReq94.Nonce = false;
        assert.equal(tspReq94.Nonce, false, "Wrong value for Nonce");

        tspReq94.Nonce = true;
        assert.equal(tspReq94.Nonce, true, "Wrong value for Nonce");
    });

    it("TSPRequest - Policy ID", function () {
        tspReq94.PolicyId = "1.2.3.4.5.6.7.8";
        assert.equal(tspReq94.PolicyId, "1.2.3.4.5.6.7.8", "Wrong value for PolicyId");

        tspReq94.PolicyId = "";
        assert.equal(tspReq94.PolicyId, "", "Wrong value for PolicyId");
    });

    it("TSPRequest - Hash Algorithm OID", function () {
        assert.equal(tspReq94.HashAlgOid, "1.2.643.2.2.9", "Wrong value for HashAlgOid");
    });

    it("TSPRequest - Add data", function () {
		
		assert.throws(() => {
            tspReq94.AddData("Test 02");
        });

        assert.doesNotThrow(() => {
            tspReq94.AddData(
                Buffer.from("Test 02")
            );
        });
    });

    it("TSPRequest - Data hash value", function () {
        assert.equal(tspReq94.DataHash.toString("hex"), "568b123799e22541ea74d677e77207ba2c3b1bf71582155a058b53ebb324363c", "Wrong GOST 34.11-94 hash value");
    });

    //---TSP-----------------------------------------
    var tsp94; // Response with GOST 34.11-94 hash alg
    var tspImported;
    var failedStamp;

    var serviceCert;
    var serviceCert94;

    it("Sending request with GOST 34.11-94", function () {
        var connSettings = new trusted.utils.ConnectionSettings();

        connSettings.Address = "http://tax4.tensor.ru/tsp/tsp.srf";

        tsp94 = new trusted.pki.TSP(tspReq94, connSettings);
        assert.notEqual(tsp94, null, "Response is empty");
    });

    it("Exporting recieved values", function () {
        var tspRespValue = tsp94.Export();
        assert.equal(Buffer.isBuffer(tspRespValue), true);
        assert.equal(tspRespValue.length > 0, true);
    });

    it("Verify", function () {
        var verifyResult = tsp94.Verify();

        assert.equal(typeof (verifyResult), "number", "Bad result value type");
        assert.equal(verifyResult, 0, "Good verify result expected (tsp94)");
    });

	it("TSA certificate", function () {
       serviceCert94 = tsp94.TSACertificate;

        assert.equal(typeof (serviceCert94), "object", "Expecting Certificate - object (tsp94)");
        assert.equal(serviceCert94.subjectFriendlyName, 'ООО "Компания "Тензор"', "Unexpected subject name for GOST 34.11-94 authority");
    });

    it("Certificate verify", function () {
        
		var certVerifyStatus = tsp94.VerifyCertificate(serviceCert94);
		

        assert.equal(typeof (certVerifyStatus), "number", "Expecting verify result - number (tsp94)");
        assert.equal(certVerifyStatus, 0, "Verify status must be 0 (good) for GOST 34.11-94 authority");
    });
	
    it("Fail info", function () {
        var failInfo = tsp94.FailInfo;

        assert.equal(typeof (failInfo), "number", "Expecting fail code - number (tsp94)");
        assert.equal(failInfo, 0, "Fail info must be 0 (good) for GOST 34.11-94 authority");
    });

    it("Status", function () {
        var status = tsp94.Status;
        assert.equal(typeof (status), "number", "Expecting status code - number (tsp)");
        assert.equal(status, 0, "Stamp status must be 0 (good) for GOST 34.11-94 authority");
    });

    it("StatusString", function () {
        var statusString = tsp94.StatusString;
        assert.equal(typeof (statusString), "string", "Expecting string with description (tsp94)");
        assert.equal(statusString, "", "Description string must be empty (good) for GOST 34.11-94 authority");
    });

    it("DataHashAlgOID", function () {
        var dataHashAlgOID = tsp94.DataHashAlgOID;
        assert.equal(typeof (dataHashAlgOID), "string", "Expecting string with OID (tsp94)");
        assert.equal(dataHashAlgOID, "1.2.643.2.2.9", "Wrong alg OID for GOST 34.11-94 authority");
    });

    it("Time stamp - Data hash value", function () {
        assert.equal(typeof (tsp94.DataHash), "object", "Expecting buffer with data - object");
        assert.equal(tsp94.DataHash.toString("hex"), "568b123799e22541ea74d677e77207ba2c3b1bf71582155a058b53ebb324363c", "Wrong GOST 34.11-94 hash value");
    });

    it("PolicyID", function () {
        var policyID = tsp94.PolicyID;
        assert.equal(typeof (policyID), "string", "Expecting string with OID (tsp94)");
        assert.equal(policyID, "1.2.643.3.58.3.1", "Wrong OID for GOST 34.11-94 authority");
    });

 
    it("Accuracy", function () {
        var accuracy = tsp94.Accuracy;
        assert.equal(typeof (accuracy), "number", "Expecting number of milliseconds (tsp94)");
        assert.equal(accuracy, 1000000, "Wrong accuracy for GOST 34.11-94 authority");
    });

    it("Ordering", function () {
        var ordering = tsp94.Ordering;
        assert.equal(typeof (ordering), "boolean", "Expecting boolean flag (tsp94)");
        assert.equal(ordering, false, "Wrong ordering for GOST 34.11-94 authority");
    });

    it("HasNonce", function () {
        var hasNonce = tsp94.HasNonce;
        assert.equal(typeof (hasNonce), "boolean", "Expecting boolean flag (tsp94)");
        assert.equal(hasNonce, true, "Wrong hasNonce for GOST 34.11-94 authority");
    });

    it("TsaName", function () {
        var tsaName = tsp94.TsaName;
        assert.equal(typeof (tsaName), "string", "Expecting string with name (tsp94)");
        assert.equal(tsaName, "directoryName: E=ca_tensor@tensor.ru,INN=007605016030,OGRN=1027600787994,OU=Удостоверяющий центр,O=ООО \"Компания \"Тензор\",STREET=Московский проспект, д.12,L=г. Ярославль,ST=76 Ярославская область,C=RU,CN=ООО \"Компания \"Тензор\"", "Wrong TsaName for GOST 34.11-94 authority");
    });

    it("TsaNameBlob", function () {
        assert.equal(typeof (tsp94.TsaNameBlob), "object", "Expecting buffer with data - object");
        assert.equal(tsp94.TsaNameBlob.toString("hex"), "a482018c308201883122302006092a864886f70d010901161363615f74656e736f724074656e736f722e7275311a301806082a85030381030101120c3030373630353031363033303118301606052a85036401120d313032373630303738373939343130302e060355040b0c27d0a3d0b4d0bed181d182d0bed0b2d0b5d180d18fd18ed189d0b8d0b920d186d0b5d0bdd182d1803130302e060355040a0c27d09ed09ed09e2022d09ad0bed0bcd0bfd0b0d0bdd0b8d18f2022d0a2d0b5d0bdd0b7d0bed180223135303306035504090c2cd09cd0bed181d0bad0bed0b2d181d0bad0b8d0b920d0bfd180d0bed181d0bfd0b5d0bad1822c20d0b42e3132311f301d06035504070c16d0b32e20d0afd180d0bed181d0bbd0b0d0b2d0bbd18c3131302f06035504080c28373620d0afd180d0bed181d0bbd0b0d0b2d181d0bad0b0d18f20d0bed0b1d0bbd0b0d181d182d18c310b30090603550406130252553130302e06035504030c27d09ed09ed09e2022d09ad0bed0bcd0bfd0b0d0bdd0b8d18f2022d0a2d0b5d0bdd0b7d0bed18022", "Wrong GOST 34.11-94 TSA name blob");
		
    });
});

describe("Request and response", function () {
	var tspReq, tsp;
	var dataBuf;
	var connSettings;
	var tsp1;
	var cadesEnabled;
	
	before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
		if (!cadesEnabled)
            this.skip();
    });
	
	beforeEach(function() { 
	    connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		tspReq = new trusted.pki.TSPRequest("1.2.643.7.1.1.2.2");
        tspReq.CertReq = true;
        tspReq.Nonce = true;
        tspReq.PolicyId = "";
        dataBuf = Buffer.from("Test 01");
        tspReq.AddData(dataBuf);
		tspReq.DataHash;
    });   
	
	it("Verify stamp without certificate", function () {
		tspReq.CertReq = false;
		tsp = new trusted.pki.TSP(tspReq, connSettings);
		assert.notEqual(tsp, null, "Response is empty");
		assert.notEqual(tsp.Verify(), 0, "Good verify result expected (tsp)");
    });
	
	it("Error PolicyID", function () {
		tspReq.PolicyId = "error";
		var tsp_err;
		assert.throws(function() {
			return tsp_err = new trusted.pki.TSP(tspReq, connSettings);
		});
    });
	
	it("Empty Data request", function () {
		var dataBuf1 = Buffer.from("");
        var tspReq1 = new trusted.pki.TSPRequest("1.2.643.7.1.1.2.2");
		tspReq1.AddData(dataBuf1);
		var tsp1 = new trusted.pki.TSP(tspReq1, connSettings);
		assert.notEqual(tsp, null, "Response is empty");
    });
	
	it("Empty Data response", function () {
		
		assert.notEqual(tsp, null, "Response is empty");
    });
});

describe("SIGNATURE PARAMS", function () {
    var sd = undefined;
	var cadesEnabled;
	
	before(function () {
        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
		if (!cadesEnabled)
            this.skip();
    });
	
    it("Set time stamp params", function () {
        var connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";

        sd = new trusted.cms.SignedData();

        var stpParams = new trusted.cms.TimestampParams();
        stpParams.stampType = trusted.cms.StampType.stContent;
        stpParams.connSettings = connSettings;
        stpParams.tspHashAlg = "1.2.643.7.1.1.2.2";

        assert.doesNotThrow(function () {
            sd.signParams = stpParams;
        });
    });

    it("Get time stamp params", function () {
        var stpParams;

        assert.doesNotThrow(function () {
            stpParams = sd.signParams;
        });

        assert.equal(stpParams.stampType, trusted.cms.StampType.stContent, "Invalid stamp type");
        assert.equal(stpParams.connSettings.Address, "http://qs.cryptopro.ru/tsp/tsp.srf", "Unexpected addres");
        assert.equal(stpParams.tspHashAlg, "1.2.643.7.1.1.2.2", "Invalid hash algorithm");
    });
});

describe("SIGNATURE WITH TIME STAMP", function () {
    var certFile = "TrustedCrypto2012-256.cer";
    var signWithTimestampSign = "sign_with_timestamp_sign.sig";
    var signWithTimestampSignDetached = "sign_with_timestamp_sign_detached.sig";
    var signWithTimestampData = "sign_with_timestamp_data.sig";
    var signWithTwoTimestamps = "sign_with_timestamp_both.sig";
    var cosignWithTimestamps = "cosign_with_timestamps.sig";
    var signDetachedWithTimestamp = "sign_with_timestamp_detached.sig";

    var cert;
    var sdTspContent, sdTspSign, sdTspBoth;
    var tspParams;
	var cadesEnabled;
	
    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        var module = new trusted.utils.ModuleInfo;
        cadesEnabled = module.cadesEnabled;
		if (!cadesEnabled)
            this.skip();
 
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        var connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";

        tspParams = new trusted.cms.TimestampParams();
        tspParams.connSettings = connSettings;
        tspParams.tspHashAlg = "1.2.643.7.1.1.2.2";
    });

    it("Creating sign with time stamp for source data", function () {
        sdTspContent = new trusted.cms.SignedData();

        sdTspContent.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 1."
        };

        tspParams.stampType = trusted.cms.StampType.stContent;
        sdTspContent.signParams = tspParams;

        assert.doesNotThrow(function () {
            sdTspContent.sign(cert);
        });

        assert.equal(sdTspContent.export() !== undefined, true, "Unable to export sign with TSP");
        sdTspContent.save(DEFAULT_OUT_PATH + "/" + signWithTimestampData, trusted.DataFormat.PEM);
    }).timeout(10000);

    it("Obtaining time stamp for source data", function () {
        var stampContent = sdTspContent.signers(0).timestamp(trusted.cms.StampType.stContent);
        assert.notEqual(stampContent, undefined, "Content timestamp must present");

        assert.equal(stampContent.DataHashAlgOID, tspParams.tspHashAlg, "Content stamp: Hash algorithm must match algorithm from request");
        assert.equal(typeof (stampContent.Time), "object", "Content stamp: Property time must return date object");

        var stampSign = sdTspContent.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.equal(stampSign, undefined, "Signature timestamp must not present");
    });

    it("Creating sign with time stamp for signature", function () {
        sdTspSign = new trusted.cms.SignedData();

        sdTspSign.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 2."
        };

        tspParams.stampType = trusted.cms.StampType.stSignature;
        sdTspSign.signParams = tspParams;

        assert.doesNotThrow(function () {
            sdTspSign.sign(cert);
        });

        assert.equal(sdTspSign.export() !== undefined, true, "Unable to export sign with TSP");
        sdTspSign.save(DEFAULT_OUT_PATH + "/" + signWithTimestampSign, trusted.DataFormat.PEM);
    }).timeout(10000);

    it("Obtaining time stamp for signature", function () {
        var stampContent = sdTspSign.signers(0).timestamp(trusted.cms.StampType.stContent);
        assert.equal(stampContent, undefined, "Content timestamp must not present");

        var stampSign = sdTspSign.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notEqual(stampSign, undefined, "Signature timestamp must present");

        assert.equal(stampSign.DataHashAlgOID, tspParams.tspHashAlg, "Signature stamp: Hash algorithm must match algorithm from request");
        assert.equal(typeof (stampSign.Time), "object", "Signature stamp: Property time must return date object");

    });

    it("Creating sign with two time stamps", function () {
        sdTspBoth = new trusted.cms.SignedData();

        sdTspBoth.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 3."
        };

        tspParams.stampType = trusted.cms.StampType.stContent | trusted.cms.StampType.stSignature;
        sdTspBoth.signParams = tspParams;

        assert.doesNotThrow(function () {
            sdTspBoth.sign(cert);
        });

        assert.notEqual(sdTspBoth.export(), undefined, "Unable to export sign with TSP");
        sdTspBoth.save(DEFAULT_OUT_PATH + "/" + signWithTwoTimestamps, trusted.DataFormat.PEM);
    }).timeout(10000);

    it("Obtaining both time stamps", function () {
        var stampContent = sdTspBoth.signers(0).timestamp(trusted.cms.StampType.stContent);
        assert.notEqual(stampContent, undefined, "Content timestamp must present");

        assert.equal(stampContent.DataHashAlgOID, tspParams.tspHashAlg, "Content stamp: Hash algorithm must match algorithm from request");
        assert.equal(typeof (stampContent.Time), "object", "Content stamp: Property time must return date object");

        var stampSign = sdTspBoth.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notEqual(stampSign, undefined, "Signature timestamp must present");

        assert.equal(stampSign.DataHashAlgOID, tspParams.tspHashAlg, "Signature stamp: Hash algorithm must match algorithm from request");
        assert.equal(typeof (stampSign.Time), "object", "Signature stamp: Property time must return date object");
    });

    it("Creating detached sign with time stamp for signature", function () {
        var sdTspSignDet = new trusted.cms.SignedData();

        sdTspSignDet.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 2.2."
        };

        tspParams.stampType = trusted.cms.StampType.stSignature;
        sdTspSignDet.signParams = tspParams;
        sdTspSignDet.policies = ["detached"];

        assert.doesNotThrow(function () {
            sdTspSignDet.sign(cert);
        });

        assert.equal(sdTspSignDet.export() !== undefined, true, "Unable to export sign with TSP");
        sdTspSignDet.save(DEFAULT_OUT_PATH + "/" + signWithTimestampSignDetached, trusted.DataFormat.PEM);
    }).timeout(10000);

    it("Obtaining time stamp for detached signature", function () {
        var sdTspSignDet = new trusted.cms.SignedData();
        sdTspSignDet.load(DEFAULT_OUT_PATH + "/" + signWithTimestampSignDetached, trusted.DataFormat.PEM);

        assert.throws(function () {
            sdTspSignDet.verify();
        }, "Verification of detached signature without content must fail");

        sdTspSignDet.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 2.2."
        };

        assert.equal(sdTspSignDet.verify(), true, "Signature with content must be able to verify");

        var stampContent = sdTspSignDet.signers(0).timestamp(trusted.cms.StampType.stContent);
        assert.equal(stampContent, undefined, "Content timestamp must not present");

        var stampSign = sdTspSignDet.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notEqual(stampSign, undefined, "Signature timestamp must present");
    });

    it("Creating cosign with stamps", function () {
        var sdCosignTsp = new trusted.cms.SignedData();

        sdCosignTsp.load(DEFAULT_OUT_PATH + "/" + signWithTimestampData, trusted.DataFormat.PEM)

        tspParams.stampType = trusted.cms.StampType.stContent | trusted.cms.StampType.stSignature;
        sdCosignTsp.signParams = tspParams;

        assert.doesNotThrow(function () {
            sdCosignTsp.sign(cert);
        });

        assert.notEqual(sdCosignTsp.export(), undefined, "Unable to export cosign with TSP");
        sdCosignTsp.save(DEFAULT_OUT_PATH + "/" + cosignWithTimestamps, trusted.DataFormat.PEM);
    });

    it("Verifying cosign with stamps", function () {
        var sdCosignTsp = new trusted.cms.SignedData();

        sdCosignTsp.load(DEFAULT_OUT_PATH + "/" + cosignWithTimestamps, trusted.DataFormat.PEM)

        var stampContent = sdCosignTsp.signers(1).timestamp(trusted.cms.StampType.stContent);
        assert.notEqual(stampContent, undefined, "Content timestamp must present");

        var stampSign = sdCosignTsp.signers(1).timestamp(trusted.cms.StampType.stSignature);
        assert.notEqual(stampSign, undefined, "Signature timestamp must present");
    }).timeout(10000);

    it("Verifying content time stamp", function () {
        var verifyResult = sdTspContent.signers(0).verifyTimestamp(trusted.cms.StampType.stContent);
        assert.equal(verifyResult, true, "Content timestamp verification");
    });

    it("Verifying signature time stamp", function () {
        var verifyResult = sdTspSign.signers(0).verifyTimestamp(trusted.cms.StampType.stSignature);
        assert.equal(verifyResult, true, "Signature timestamp verification");
    });

    it("Verifying absent time stamp", function () {
        assert.throws(function () {
            var verifyResult = sdTspSign.signers(0).verifyTimestamp(trusted.cms.StampType.stContent);
        }, "Must throw error if timestamp is absent");
    });

    it("Verifying two time stamps at a time", function () {
        assert.throws(function () {
            var verifyResult = sdTspBoth.signers(0).verifyTimestamp(trusted.cms.StampType.stContent | trusted.cms.StampType.stSignature);
        }, "Must be unable to verify two time stamps");
    });

    it("Verifying time stamp with damaged source", function () {
        var sdTspDetached = new trusted.cms.SignedData();

        sdTspDetached.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp 4."
        };

        sdTspDetached.policies = ["detached"];

        tspParams.stampType = trusted.cms.StampType.stContent;
        sdTspDetached.signParams = tspParams;

        assert.doesNotThrow(function () {
            sdTspDetached.sign(cert);
        });

        assert.notEqual(sdTspDetached.export(), undefined, "Unable to export sign with TSP");
        sdTspDetached.save(DEFAULT_OUT_PATH + "/" + signDetachedWithTimestamp, trusted.DataFormat.PEM);

        var sdTspDamaged = new trusted.cms.SignedData();
        sdTspDamaged.load(DEFAULT_OUT_PATH + "/" + signDetachedWithTimestamp, trusted.DataFormat.PEM);
        sdTspDamaged.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Signature with time stamp Y."
        };

        assert.equal(sdTspDamaged.signers(0).verifyTimestamp(trusted.cms.StampType.stContent), false, "Verification of timestamp with damaged content must fail");
    });
});

