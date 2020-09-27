"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("CAdES", function () {
    var certFile = "TrustedCrypto2012-256.cer";
    var signCades1 = "signCades1.txt.sig";
    var signCades2 = "signCades2.txt.sig";
    var signCadesAncCosign = "signCadesAndCosign.txt.sig";
    //var signCadesWithExpiredCert = "signCadesExpiredCert.txt.sig";
    var attachSignFile = "sign2012-256_att.txt.sig";
    var signCadesDetached = "signCadesDetached.txt.sig";
    var signCadesDetached2 = "signCadesDetached2.txt.sig";
    var signFile_att = "sign2012-256_att.txt.sig";
    var signCadesDamaged = "signCadesDamaged.txt.sig";

    var cert;
    var sdCadesLoad;
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
    });

    it("Create CAdES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";

        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "CAdES test 1"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/" + signCades1, trusted.DataFormat.PEM);
    }).timeout(10000);

    it("Create CAdES with wrong proxy settings", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
        connSettings.ProxyAddress = "http://example.com";

        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "CAdES test 2"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.throws(function () {
            sdCades.sign(cert);
        });
    }).timeout(10000);

    it("Add CAdES cosignature", function () {
        var signers;
        var signer;

        var cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att);
        signers = cms.signers();
        signer = signers.items(0);

        var connSettings = new trusted.utils.ConnectionSettings();
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        cms.signParams = cadesParams;

        assert.doesNotThrow(function () {
            cms.sign(cert);
        });

        assert.notStrictEqual(cms.export(), undefined, "Unable to export signature");
        cms.save(DEFAULT_OUT_PATH + "/" + signCades2, trusted.DataFormat.DER);
    }).timeout(10000);


    it("IsCades method", function () {
        sdCadesLoad = new trusted.cms.SignedData();
        sdCadesLoad.load(DEFAULT_OUT_PATH + "/" + signCades1, trusted.DataFormat.PEM);

        assert.strictEqual(typeof (sdCadesLoad.signers(0).isCades), "boolean", "isCades type must be boolean");
        assert.strictEqual(sdCadesLoad.signers(0).isCades, true, "Signature must be CAdES");
    });

    it("IsCades method for not cades", function () {
        var sdNotCades = new trusted.cms.SignedData();
        sdNotCades.load(DEFAULT_RESOURCES_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

        assert.strictEqual(typeof (sdNotCades.signers(0).isCades), "boolean", "isCades type must be boolean");
        assert.strictEqual(sdNotCades.signers(0).isCades, false, "Signature must not be CAdES");
    });

	it("Is not cades for sign with TSP", function () {
        var sdNotCades = new trusted.cms.SignedData();
        sdNotCades.load(DEFAULT_RESOURCES_PATH + "/TSP.xls.sig", trusted.DataFormat.PEM);
        assert.strictEqual(sdNotCades.signers(0).isCades, false, "Signature must not be CAdES");
    });
	
	it("Verify single CAdES", function () {
        assert.strictEqual(sdCadesLoad.verify(), true, "Verification must success");
        assert.strictEqual(sdCadesLoad.verify(sdCadesLoad.signers(0)), true, "Signer verification must success");
    }).timeout(10000);

    //it("Verify CAdES with expired cert", function () {
    //    // TODO: obtain CAdES signature with expired signing certificate
    //    var sdCadesWithExpiredCert = new trusted.cms.SignedData();
    //    sdCadesWithExpiredCert.load(DEFAULT_RESOURCES_PATH + "/" + signCadesWithExpiredCert, trusted.DataFormat.PEM);

    //    assert.strictEqual(signCadesWithExpiredCert.isCades, true, "Signature must be CAdES");

    //    assert.strictEqual(sdCadesWithExpiredCert.verify(), true, "CAdES with expired cert is not valid");
    //    assert.strictEqual(sdCadesWithExpiredCert.verify(sdCadesWithExpiredCert.signers(0)), true, "CAdES signer with expired cert is not valid");
    //}).timeout(10000);

    it("Verify CAdES with not enhanced cosigner", function () {
        var sdCadesCosigners = new trusted.cms.SignedData();
        sdCadesCosigners.load(DEFAULT_RESOURCES_PATH + "/" + signCadesAncCosign, trusted.DataFormat.DER);
        assert.strictEqual(sdCadesCosigners.signers(0).isCades, false, "First signature must not be CAdES");
        assert.strictEqual(sdCadesCosigners.signers(1).isCades, true, "Second signature must be CAdES");

        assert.strictEqual(sdCadesCosigners.verify(), true, "Verification must success");

        assert.strictEqual(sdCadesCosigners.verify(sdCadesCosigners.signers(0)), true, "Not CAdES cosigner verification must succed (attached signature)");
        assert.strictEqual(sdCadesCosigners.verify(sdCadesCosigners.signers(1)), true, "CAdES cosigner verification must succed (attached signature)");
    }).timeout(10000);

    it("Verify detached CAdES", function () {
        var sdCadesDetached = new trusted.cms.SignedData();
        sdCadesDetached.load(DEFAULT_RESOURCES_PATH + "/" + signCadesDetached, trusted.DataFormat.DER);
        sdCadesDetached.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "detached content"
        };

        assert.strictEqual(sdCadesDetached.signers(0).isCades, true, "Signature must be CAdES");

        assert.strictEqual(sdCadesDetached.verify(), true, "Detached CAdES verification must cucced");
        assert.strictEqual(sdCadesDetached.verify(sdCadesDetached.signers(0)), true, "Detached CAdES signer must be valid");
    }).timeout(10000);

    it("Verify detached CAdES with not enhanced cosigner", function () {
        var sdCadesDetached2 = new trusted.cms.SignedData();
        sdCadesDetached2.load(DEFAULT_RESOURCES_PATH + "/" + signCadesDetached2, trusted.DataFormat.DER);
        sdCadesDetached2.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "detached content"
        };

        assert.strictEqual(sdCadesDetached2.signers(0).isCades, false, "First signature must not be CAdES");
        assert.strictEqual(sdCadesDetached2.signers(1).isCades, true, "Second signature must be CAdES");

        assert.strictEqual(sdCadesDetached2.verify(), true, "Detached CAdES verification must succed");

        assert.strictEqual(sdCadesDetached2.verify(sdCadesDetached2.signers(0)), true, "Not CAdES cosigner verification must succed (detached signature)");
        assert.strictEqual(sdCadesDetached2.verify(sdCadesDetached2.signers(1)), true, "CAdES cosigner verification must succed (detached signature)");
    }).timeout(10000);

    it("Verify damaged CAdES", function () {
        var sdCadesDamaged = new trusted.cms.SignedData();
        sdCadesDamaged.load(DEFAULT_RESOURCES_PATH + "/" + signCadesDamaged, trusted.DataFormat.DER);

        assert.strictEqual(sdCadesDamaged.signers(0).isCades, true, "Signature must be CAdES");

        assert.strictEqual(sdCadesDamaged.verify(), false, "Damaged CAdES must not be valid");
    }).timeout(10000);

    it("Obtaining revocation values", function () {
        assert.strictEqual(sdCadesLoad.signers(0).isCades, true, "Signature must be CAdES");

        var revValues = sdCadesLoad.signers(0).revocationValues;
        assert.strictEqual(typeof (revValues), "object", "Must be array of revocation values");
        assert.strictEqual(revValues.length, 1, "Array must contain single ocsp response (for CAdES from test 'Create CAdES')");
        var resp1 = new trusted.pki.OCSP(revValues[0]);
        assert.strictEqual(resp1.RespStatus, trusted.pki.CPRespStatus.successful, "Response must be valid");

        var ocspResp = sdCadesLoad.signers(0).ocspResp;
        assert.notStrictEqual(typeof (ocspResp), "undefined", "Must return ocsp response for signer certificate (if present)");
        assert.strictEqual(ocspResp.Verify(), 0, "Ocsp response must be valid");
        assert.strictEqual(ocspResp.Status(0), trusted.pki.CPCertStatus.Good, "Revocation status must be 'Good'");
    });

    it("Obtaining timestamp values", function () {
        assert.strictEqual(sdCadesLoad.signers(0).isCades, true, "Signature must be CAdES");

        var stampEsc = sdCadesLoad.signers(0).timestamp(trusted.cms.StampType.stEscStamp);
        assert.notStrictEqual(stampEsc, undefined, "Esc timestamp must present");
        assert.strictEqual(stampEsc.Verify(), 0, "Esc timestamp verification");

        var stampSign = sdCadesLoad.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notStrictEqual(stampSign, undefined, "Signature timestamp must present");
        assert.strictEqual(stampSign.Verify(), 0, "Signature timestamp verification");
    });
	
    it("Certificate values", function () {
        assert.strictEqual(sdCadesLoad.signers(0).isCades, true, "Signature must be CAdES");

        var certValues = sdCadesLoad.signers(0).certificateValues;
        assert.strictEqual(typeof (certValues), "object", "Must be certificate collection object");
        assert.notStrictEqual(certValues.length, 0, "Collection must contain few certificates to verify CAdES certs");
    });

	it("Create CAdES for file 1 MB", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
		var file1 = "file1.txt";
		
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + file1
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/" + "file1.txt.sig", trusted.DataFormat.PEM); 
    }).timeout(30000);

	it("Verify CAdES file 1 MB", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/file1.txt.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000); 
	
	/*it("Create CAdES for file 10 MB", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
		var file10 = "file10.txt";
		
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + file10
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/" + "file10.txt.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify CAdES file 10 MB", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/file10.txt.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000); 
	
	it("Create CAdES for file 73 MB", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
		var file73 = "file73.txt";
		
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + file73
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/" + "file73.txt.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify CAdES file 73 MB", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/file73.txt.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000); 
	
	it("Create CAdES for file 100 MB", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
		var file100 = "file100.txt";
		
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		//cert = DEFAULT_RESOURCES_PATH + "";
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + file100
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/" + "file100.txt.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify CAdES file 100 MB", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/file100.txt.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(30000); 
	*/
	/*it("Create CAdES for file with qualified certificate", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
				
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		var cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/qual_cert2012.cer", trusted.DataFormat.PEM);
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/файл5_qual.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);
	*/
	
	it("Create CAdES for file + add CADES with another hash algorithm", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
//        var logger = trusted.common.Logger.start(DEFAULT_OUT_PATH + "/logger_cades.txt", trusted.LoggerLevel.ALL);	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        //cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        }, "Error while creating first CAdES with GOST 2012 256");

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/файл5_cades.pdf.sig", trusted.DataFormat.PEM);
		
		var cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-512.cer", trusted.DataFormat.DER);
		var sdCades2 = new trusted.cms.SignedData();
		sdCades2.load(DEFAULT_OUT_PATH + "/файл5_cades.pdf.sig", trusted.DataFormat.PEM);
		sdCades2.signParams = cadesParams;
		assert.doesNotThrow(function () {
            sdCades2.sign(cert2);
        }, "Error while creating second CAdES with GOST 2012 512");
		sdCades2.save(DEFAULT_OUT_PATH + "/файл5_cades.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify CAdES with two different signes", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_cades.pdf.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
	/*it("Create CAdES for file + add CADES qualitify cert", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
//        var logger = trusted.common.Logger.start(DEFAULT_OUT_PATH + "/logger_cades.txt", trusted.LoggerLevel.ALL);	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/файл5_cades_qual.pdf.sig", trusted.DataFormat.PEM);
		
		var cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/qual_cert2012.cer", trusted.DataFormat.PEM);
		var sdCades2 = new trusted.cms.SignedData();
		sdCades2.load(DEFAULT_OUT_PATH + "/файл5_cades_qual.pdf.sig", trusted.DataFormat.PEM);
		sdCades2.signParams = cadesParams;
		assert.doesNotThrow(function () {
            sdCades.sign(cert2);
        });
		sdCades.save(DEFAULT_OUT_PATH + "/файл5_cades_qual.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);
	*/
	
	it("Create CAdES for file + add CADES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };

        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/файл5_two_cades.pdf.sig", trusted.DataFormat.PEM);
		
		var cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer", trusted.DataFormat.DER);
		assert.doesNotThrow(function () {
            sdCades.sign(cert2);
        });
		sdCades.save(DEFAULT_OUT_PATH + "/файл5_two_cades.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify CAdES with two signes", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_two_cades.pdf.sig", trusted.DataFormat.PEM);
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
		assert.strictEqual(cades.signers(0).isCades, true, "First signature must be CAdES");
		assert.strictEqual(cades.signers(1).isCades, true, "Second signature must be CAdES");
    }).timeout(10000);
	
	it("CMS + add CAdES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        /*sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
		*/
		sdCades.load(DEFAULT_RESOURCES_PATH + "/sign2012-256_att.txt.sig", trusted.DataFormat.PEM);
		
        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;
	
		assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });
		sdCades.save(DEFAULT_OUT_PATH + "/cms_and_cades.txt.sig", trusted.DataFormat.PEM);
    }).timeout(30000);
	
	it("Create detached CAdES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();
		sdCades.policies = ["detached"];

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
		fs.copyFileSync(DEFAULT_RESOURCES_PATH + "/файл5.pdf", DEFAULT_OUT_PATH + "/cades_detached.pdf");
		var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;
	
		assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });
		
		sdCades.save(DEFAULT_OUT_PATH + "/cades_detached.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);
	
	it("Verify detached CAdES", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/cades_detached.pdf.sig", trusted.DataFormat.PEM);
		cades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
		assert.strictEqual(cades.signers(0).isCades, true, "Signature must be CAdES");
    }).timeout(10000);
	
	it("Create detached CAdES for file + add CADES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
		
		sdCades.policies = ["detached"];
		
        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

        assert.doesNotThrow(function () {
            sdCades.sign(cert);
        });

        assert.notStrictEqual(sdCades.export(), undefined, "Unable to export CAdES");
        sdCades.save(DEFAULT_OUT_PATH + "/файл5_det_two_cades.pdf.sig", trusted.DataFormat.PEM);
		
		var cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer", trusted.DataFormat.DER);
		assert.doesNotThrow(function () {
            sdCades.sign(cert2);
        });
		sdCades.save(DEFAULT_OUT_PATH + "/файл5_det_two_cades.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify detached CAdES with two signes", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_det_two_cades.pdf.sig", trusted.DataFormat.PEM);
		cades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
	it("Detached CAdES with two signes isCades", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_det_two_cades.pdf.sig", trusted.DataFormat.PEM);
		cades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        assert.strictEqual(cades.signers(0).isCades, true, "First signature must be CAdES");
		assert.strictEqual(cades.signers(1).isCades, true, "Second signature must be CAdES");
    });
	
	it("Add third CADES", function () {
        var sdCades;
        var connSettings = new trusted.utils.ConnectionSettings();
	
        connSettings.Address = "http://qs.cryptopro.ru/tsp/tsp.srf";
		
        sdCades = new trusted.cms.SignedData();

        sdCades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
		
		sdCades.load(DEFAULT_OUT_PATH + "/файл5_det_two_cades.pdf.sig", trusted.DataFormat.PEM);
		
        var cadesParams = new trusted.cms.CadesParams();
        cadesParams.cadesType = trusted.cms.CadesType.ctCadesXLT1;
        cadesParams.connSettings = connSettings;
        cadesParams.tspHashAlg = "1.2.643.7.1.1.2.2";
        sdCades.signParams = cadesParams;

       	var cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/TrustedCrypto2012-256.cer", trusted.DataFormat.DER);
		assert.doesNotThrow(function () {
            sdCades.sign(cert2);
        });
		sdCades.save(DEFAULT_OUT_PATH + "/файл5_det_three_cades.pdf.sig", trusted.DataFormat.PEM);
    }).timeout(30000);

	it("Verify detached CAdES with three signes", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_det_three_cades.pdf.sig", trusted.DataFormat.PEM);
		cades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
	it("Detached CAdES with three signes isCades", function () {
		var cades = new trusted.cms.SignedData();
        cades.load(DEFAULT_OUT_PATH + "/файл5_det_three_cades.pdf.sig", trusted.DataFormat.PEM);
		cades.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        assert.strictEqual(cades.signers(0).isCades, true, "First signature must be CAdES");
		assert.strictEqual(cades.signers(1).isCades, true, "Second signature must be CAdES");
		assert.strictEqual(cades.signers(2).isCades, true, "Third signature must be CAdES");
    });
});
    
describe("Verify CAdES created in CryptoARM 5", function () {
	var cades, cades2, cades3, cades4;
	cades = new trusted.cms.SignedData();
	cades2 = new trusted.cms.SignedData();
	cades3 = new trusted.cms.SignedData();
	cades4 = new trusted.cms.SignedData();
	var cadesEnabled;
	
	 before(function () {
		var module = new trusted.utils.ModuleInfo;
			cadesEnabled = module.cadesEnabled;
			if (!cadesEnabled)
				this.skip();
	 });		
		
	it("Verify CAdES attached", function () {
		cades.load(DEFAULT_RESOURCES_PATH + "/OCSP_att.docx.sig", trusted.DataFormat.PEM);
		assert.strictEqual(cades.signers(0).isCades, true, "Signature must be CAdES");
        assert.strictEqual(cades.verify(), true, "Verification must success");
        assert.strictEqual(cades.verify(cades.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
    it("Obtaining timestamp values attached", function () {
		assert.strictEqual(cades.signers(0).isCades, true, "Signature must be CAdES");

        var stampEsc = cades.signers(0).timestamp(trusted.cms.StampType.stEscStamp);
        assert.notStrictEqual(stampEsc, undefined, "Esc timestamp must present");
        assert.strictEqual(stampEsc.Verify(), 0, "Esc timestamp verification");

        var stampSign = cades.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notStrictEqual(stampSign, undefined, "Signature timestamp must present");
        assert.strictEqual(stampSign.Verify(), 0, "Signature timestamp verification");
    });
	
	it("Verify CAdES detached", function () {
		cades2.load(DEFAULT_RESOURCES_PATH + "/OCSP_det.docx.sig", trusted.DataFormat.PEM);
		cades2.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл2.docx"
        };
		assert.strictEqual(cades2.signers(0).isCades, true, "Signature must be CAdES");
        assert.strictEqual(cades2.verify(), true, "Verification must success");
        assert.strictEqual(cades2.verify(cades2.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
    it("Obtaining timestamp values detached", function () {
		cades2.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл2.docx"
        };
        assert.strictEqual(cades2.signers(0).isCades, true, "Signature must be CAdES");

        var stampEsc = cades2.signers(0).timestamp(trusted.cms.StampType.stEscStamp);
        assert.notStrictEqual(stampEsc, undefined, "Esc timestamp must present");
        assert.strictEqual(stampEsc.Verify(), 0, "Esc timestamp verification");

        var stampSign = cades2.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notStrictEqual(stampSign, undefined, "Signature timestamp must present");
        assert.strictEqual(stampSign.Verify(), 0, "Signature timestamp verification");
    });
	
	it("Verify CAdES with expired certificate", function () {
		cades3.load(DEFAULT_RESOURCES_PATH + "/OCSP_exp_cert.pdf.sig", trusted.DataFormat.PEM);
		assert.strictEqual(cades3.signers(0).isCades, true, "Signature must be CAdES");
        assert.strictEqual(cades3.verify(), true, "Verification must success");
        assert.strictEqual(cades3.verify(cades3.signers(0)), true, "Signer verification must success");
    }).timeout(10000);
	
    it("Obtaining timestamp values of expired certificate", function () {
		assert.strictEqual(cades3.signers(0).isCades, true, "Signature must be CAdES");

        var stampEsc = cades3.signers(0).timestamp(trusted.cms.StampType.stEscStamp);
        assert.notStrictEqual(stampEsc, undefined, "Esc timestamp must present");
        assert.strictEqual(stampEsc.Verify(), 0, "Esc timestamp verification");

        var stampSign = cades3.signers(0).timestamp(trusted.cms.StampType.stSignature);
        assert.notStrictEqual(stampSign, undefined, "Signature timestamp must present");
        assert.strictEqual(stampSign.Verify(), 0, "Signature timestamp verification");
    });
});
