"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("SIGN 2001", function () {
    var certFile = "TrustedCrypto2001.cer";
   	var signFile_att = "sign2001_att.txt.sig";
	var signFile_det = "sign2001_det.txt.sig";
	var cert;
    var cms;
	var policies;

        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
			}
        });

		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
		
		it("Load attached sign", function () {
			cms = new trusted.cms.SignedData();
			cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att, trusted.DataFormat.PEM);
		});
		
		it("Verify attached signature", function () {
            assert.equal(cms.verify(), true, "Signature is valid");
        });
		
		it("Load detached sign", function () {
			cms = new trusted.cms.SignedData();
			cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_det, trusted.DataFormat.PEM);
			cms.content = {
				type: trusted.cms.SignedDataContentType.url,
				data: DEFAULT_RESOURCES_PATH + "/test.txt"
			};
		});
		
		it("Verify detached signature", function () {
			assert.equal(cms.verify(), true, "Signature is valid");
        });
		
		it("Sign data", function () {
            var policies;

            var sd = new trusted.cms.SignedData();

            sd.policies = ["detached"];

            sd.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "Hello world"
            };

            assert.throws(function() {
				return sd.sign(cert);
            });
        });
		
		it("Add sign", function () {
			cms = new trusted.cms.SignedData();
			cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att, trusted.DataFormat.PEM);
	        cms.policies = [];
			assert.throws(function() {
				return cms.sign(cert);
			});
		});
});

describe("SIGN 2012-256", function () {
    var certFile = "TrustedCrypto2012-256.cer";
    var detachSignFile = "testsig2012-256_det.sig";
    var attachSignFile = "testsig2012-256_at.sig";
    var derSigFile_det_noattr = "testsig2012-256_der_det.sig";
    var derSigFile_att_noattr = "testsig2012-256_der_att.sig";
	var signFile_att = "sign2012-256_att.txt.sig";
	var signFile_det = "sign2012-256_det.txt.sig";
	var File = "";

    describe("SIGNED_DATA: detached and with attributes in base64", function () {
        var cert;
        var cms;
        var sd;
        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
            }

            cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
        });

        it("Sign data", function () {
            var signer;
            var policies;

            sd = new trusted.cms.SignedData();

            sd.policies = ["detached"];

            sd.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "Hello world"
            };

            sd.sign(cert);
            assert.equal(sd.export() !== null, true, "sd.export()");

        });

        it("Write sign data to file", function () {
            sd.save(DEFAULT_OUT_PATH + "/" + detachSignFile, trusted.DataFormat.PEM);

        });

        it("Verify signature", function () {
            assert.equal(sd.verify() !== false, true, "Signature is not valid");
        });

        it("load", function () {
            var signers;
            var signer;
            var signerId;

            cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/" + detachSignFile, trusted.DataFormat.PEM);

            assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
            assert.equal(cms.certificates().length, 1, "Wrong certificates length");
        });

        it("Verify detached signature", function () {
            assert.equal(cms.isDetached(), true, "Attached");
        });

		it("Verify attrebutes in signature", function() {
            var signer = new trusted.cms.Signer();
			var signers = new trusted.cms.SignerCollection();
			signer = cms.signers(0);
			assert.equal(typeof (signer.signingTime), "object", "No attrebutes");
		});

        it("Verify encoding in signature: base64", function () {
            var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + detachSignFile);
            assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, false, "DER");
        });

        it("Get content of Signed Data", function () {
            assert.equal(cms.content !== null, true, "Content of SignedData is null");
        });

        it("export PEM", function () {
            var buf = cms.export(trusted.DataFormat.PEM);

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
        });

        it("export Default", function () {
            var buf = cms.export();

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
        });

        it("export DER", function () {
            var buf = cms.export(trusted.DataFormat.DER);

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
        });
    });


    describe("SIGNED_DATA: attached and without attributes in der", function () {
        var cert;
        var cms;
        //	var certFile = "TrustedCrypto2012-256.cer";
        var sd;
        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
            }

            cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
        });

        it("Sign data", function () {
            var signer;
            var policies;

            sd = new trusted.cms.SignedData();

            sd.policies = ["noAttributes"];

            sd.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "Hello world"
            };

            sd.sign(cert);
            assert.equal(sd.export() !== null, true, "sd.export()");

        });

        it("Write sign data to file", function () {
            sd.save(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);

        });

        it("Verify signature", function () {
            assert.equal(sd.verify() !== false, true, "Signature is not valid");
        });

        it("load", function () {
            var signers;
            var signer;
            var signerId;

            cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);


		});

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);
                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify attached signature", function () {
                assert.equal(cms.isDetached(), false, "Dettached");
            });

            it("Verify attrebutes in signature", function() {
                  var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "undefined", "Attrebutes are present");
            });

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
    });

    describe("SIGNED_DATA: attached in PEM", function () {
            var cert;
            var cms;
            //	var certFile = "TrustedCrypto2012-256.cer";
            var sd;
            before(function () {
                try {
                    fs.statSync(DEFAULT_OUT_PATH).isDirectory();
                } catch (err) {
                    fs.mkdirSync(DEFAULT_OUT_PATH);
                }

                cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
            });

            it("Sign data", function () {
                var signer;
                var policies;

                sd = new trusted.cms.SignedData();

                sd.policies = [];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            });

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

            });

            it("Verify attached signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });

            it("load", function () {
                var signers;
                var signer;
                var signerId;

                cms = new trusted.cms.SignedData();
                cms.load(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify attached signature", function () {
                assert.equal(cms.isDetached(), false, "Dettached");
            });

			it("Verify attrebutes in signature", function() {
                   var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "object", "No Attrebutes");
            });

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
        });

    describe("SIGNED_DATA: detached and without attributes in der", function () {
            var cert;
            var cms;
            //	var certFile = "TrustedCrypto2012-256.cer";
            var sd;

            before(function () {
                try {
                    fs.statSync(DEFAULT_OUT_PATH).isDirectory();
                } catch (err) {
                    fs.mkdirSync(DEFAULT_OUT_PATH);
                }

                cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
            });

            it("Sign data", function () {
                var signer;
                var policies;

                sd = new trusted.cms.SignedData();

                sd.policies = ["noAttributes", "detached"];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            }).timeout(30000);

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + derSigFile_det_noattr);

            });

            it("Verify attached signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });

            it("load", function () {
                var signers;
                var signer;
                var signerId;

                cms = new trusted.cms.SignedData();
                cms.load(DEFAULT_OUT_PATH + "/" + derSigFile_det_noattr);

                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify detached signature", function () {
                assert.equal(cms.isDetached(), true, "Dettached");
            });

			it("Verify attrebutes in signature", function() {
                   var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "undefined", "Attrebutes are present");
            });

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
    });

	describe("SIGNED_DATA: add sign attached", function () {
		var cert;
        var cms;
		var policies;

        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
			}
        });

		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

		it("add sign", function () {
			cms = new trusted.cms.SignedData();
			cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att, trusted.DataFormat.PEM);
		//	assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");


			cms.policies = [];
			cms.sign(cert);
			cms.save(DEFAULT_OUT_PATH + "/" + signFile_att);
		});
	});

});

describe("SIGN 2012-512", function () {
    var certFile = "TrustedCrypto2012-512.cer";
    var detachSignFile = "testsig2012-512_det.sig";
    var attachSignFile = "testsig2012-512_at.sig";
    var derSigFile_det_noattr = "testsig2012-512_der_det.sig";
    var derSigFile_att_noattr = "testsig2012-512_der_att.sig";
	var signFile_att = "sign2012-512_att.txt.sig";
	var signFile_det = "sign2012-512_det.txt.sig";
	var File = "";

    describe("SIGNED_DATA: detached and with attributes in base64", function () {
        var cert;
        var cms;
        var sd;
        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
            }

            cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
        });

        it("Sign data", function () {
            var signer;
            var policies;

            sd = new trusted.cms.SignedData();

            sd.policies = ["detached"];

            sd.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "Hello world"
            };

            sd.sign(cert);
            assert.equal(sd.export() !== null, true, "sd.export()");

        });

        it("Write sign data to file", function () {
            sd.save(DEFAULT_OUT_PATH + "/" + detachSignFile, trusted.DataFormat.PEM);

        });

        it("Verify signature", function () {
            assert.equal(sd.verify() !== false, true, "Signature is not valid");
        });

        it("load", function () {
            var signers;
            var signer;
            var signerId;

            cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/" + detachSignFile, trusted.DataFormat.PEM);

            assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
            assert.equal(cms.certificates().length, 1, "Wrong certificates length");
        });

        it("Verify detached signature", function () {
            assert.equal(cms.isDetached(), true, "Attached");
        });

    	it("Verify attrebutes in signature", function() {
            var signer = new trusted.cms.Signer();
			var signers = new trusted.cms.SignerCollection();
			signer = cms.signers(0);
			assert.equal(typeof (signer.signingTime), "object", "No attrebutes");
        });

        it("Verify encoding in signature: base64", function () {
            var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + detachSignFile);
            assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, false, "DER");
        });

        it("Get content of Signed Data", function () {
            assert.equal(cms.content !== null, true, "Content of SignedData is null");
        });

        it("export PEM", function () {
            var buf = cms.export(trusted.DataFormat.PEM);

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
        });

        it("export Default", function () {
            var buf = cms.export();

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
        });

        it("export DER", function () {
            var buf = cms.export(trusted.DataFormat.DER);

            assert.equal(Buffer.isBuffer(buf), true);
            assert.equal(buf.length > 0, true);
            assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
        });
    });


    describe("SIGNED_DATA: attached and without attributes in der", function () {
        var cert;
        var cms;
        //	var certFile = "TrustedCrypto2012-256.cer";
        var sd;
        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
            }

            cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
        });

        it("Sign data", function () {
            var signer;
            var policies;

            sd = new trusted.cms.SignedData();

            sd.policies = ["noAttributes"];

            sd.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "Hello world"
            };

            sd.sign(cert);
            assert.equal(sd.export() !== null, true, "sd.export()");

        });

        it("Write sign data to file", function () {
            sd.save(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);

        });

        it("Verify signature", function () {
            assert.equal(sd.verify() !== false, true, "Signature is not valid");
        });

        it("load", function () {
            var signers;
            var signer;
            var signerId;

            cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);


		});

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);
                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify attached signature", function () {
                assert.equal(cms.isDetached(), false, "Dettached");
            });

        	it("Verify attrebutes in signature", function() {
                var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "undefined", "Attrebutes are present");
			});

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
    });

    describe("SIGNED_DATA: attached in PEM", function () {
            var cert;
            var cms;
            //	var certFile = "TrustedCrypto2012-256.cer";
            var sd;
            before(function () {
                try {
                    fs.statSync(DEFAULT_OUT_PATH).isDirectory();
                } catch (err) {
                    fs.mkdirSync(DEFAULT_OUT_PATH);
                }

                cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
            });

            it("Sign data", function () {
                var signer;
                var policies;

                sd = new trusted.cms.SignedData();

                sd.policies = [];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            });

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

            });

            it("Verify attached signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });

            it("load", function () {
                var signers;
                var signer;
                var signerId;

                cms = new trusted.cms.SignedData();
                cms.load(DEFAULT_OUT_PATH + "/" + attachSignFile, trusted.DataFormat.PEM);

                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify attached signature", function () {
                assert.equal(cms.isDetached(), false, "Dettached");
            });

         	it("Verify attrebutes in signature", function() {
				var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "object", "No Attrebutes");
			});

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
        });

    describe("SIGNED_DATA: detached and without attributes in der", function () {
            var cert;
            var cms;
            var sd;

            before(function () {
                try {
                    fs.statSync(DEFAULT_OUT_PATH).isDirectory();
                } catch (err) {
                    fs.mkdirSync(DEFAULT_OUT_PATH);
                }

                cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
            });

            it("Sign data", function () {
                var signer;
                var policies;

                sd = new trusted.cms.SignedData();

                sd.policies = ["noAttributes", "detached"];

                sd.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: "Hello world"
                };

                sd.sign(cert);
                assert.equal(sd.export() !== null, true, "sd.export()");

            }).timeout(30000);

            it("Write sign data to file", function () {
                sd.save(DEFAULT_OUT_PATH + "/" + derSigFile_det_noattr);

            });

            it("Verify attached signature", function () {
                assert.equal(sd.verify() !== false, true, "Signature is not valid");
            });

            it("load", function () {
                var signers;
                var signer;
                var signerId;

                cms = new trusted.cms.SignedData();
                cms.load(DEFAULT_OUT_PATH + "/" + derSigFile_det_noattr);

                assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
                assert.equal(cms.certificates().length, 1, "Wrong certificates length");

            });

            it("Verify detached signature", function () {
                assert.equal(cms.isDetached(), true, "Dettached");
            });

           	it("Verify attrebutes in signature", function() {
                var signer = new trusted.cms.Signer();
				var signers = new trusted.cms.SignerCollection();
				signer = cms.signers(0);
				assert.equal(typeof (signer.signingTime), "undefined", "Attrebutes are present");
            });

            it("Verify encoding in signature: DER", function () {
                var signFileContent = fs.readFileSync(DEFAULT_OUT_PATH + "/" + derSigFile_att_noattr);
                assert.equal(signFileContent.indexOf("-----BEGIN CMS-----") === -1, true, "PEM");
            });

            it("Get content of Signed Data", function () {
                assert.equal(cms.content !== null, true, "Content of SignedData is null");
            });

            it("export PEM", function () {
                var buf = cms.export(trusted.DataFormat.PEM);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
            });

            it("export Default", function () {
                var buf = cms.export();

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });

            it("export DER", function () {
                var buf = cms.export(trusted.DataFormat.DER);

                assert.equal(Buffer.isBuffer(buf), true);
                assert.equal(buf.length > 0, true);
                assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
            });
    });

    describe("SIGNED_DATA: add sign attached", function () {
		var cert;
        var cms;
		var policies;

        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
			}
        });

		it("add sign", function () {
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

		cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att, trusted.DataFormat.PEM);
	//	assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");


        cms.policies = [];
        cms.sign(cert);
		cms.save(DEFAULT_OUT_PATH + "/" + signFile_att);
		});
	});

});

describe("SIGNED_FILE", function () {
    var cert;
    var cms;
    var policies;
    var certFile = "TrustedCrypto2012-256.cer";
    var File = "файл4.txt";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    })

    it("Sign file", function () {
        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();

        cms.policies = [];

        cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + File
        };
        cms.sign(cert);
        cms.save(DEFAULT_OUT_PATH + "/файл4.txt.sig");
    });

    it("Sign empty file", function () {
        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();

        cms.policies = [];

        assert.throws(function () {
            return cms.content = {
                type: trusted.cms.SignedDataContentType.url,
                data: DEFAULT_RESOURCES_PATH + "/empty.txt"
            };
        });

        assert.throws(function () {
            return cms.sign(cert);
        });

        cms.save(DEFAULT_OUT_PATH + "/empty.txt.sig");
	});

    it("Signing not existing file", function () {
        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();

        cms.policies = [];
		assert.throws(function() {
            return cms.content = {
                type: trusted.cms.SignedDataContentType.url,
                data: DEFAULT_RESOURCES_PATH + "/not_exist.txt"
            };
        });
	});

	it("Add sign detached", function () {
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл5.pdf.sig", trusted.DataFormat.PEM);
        cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        cms.policies = [];
        cms.sign(cert);
		cms.save(DEFAULT_OUT_PATH + "/файл5.pdf.sig");
	});
	
	it("Add third sign detached", function () {
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл5.pdf.sig", trusted.DataFormat.PEM);
        cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл5.pdf"
        };
        cms.policies = [];
        cms.sign(cert);
		cms.sign(cert);
		cms.save(DEFAULT_OUT_PATH + "/файл5_three_sign_det.pdf.sig");
	});
	
	it("Add third sign attached", function () {
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/two_signs.txt.sig", trusted.DataFormat.PEM);
        cms.policies = [];
        cms.sign(cert);
		cms.save(DEFAULT_OUT_PATH + "/three_sign_att.txt.sig");
	});

});

describe("SIGNED FILE WITH DIFFERENT HASH ALGOEITHMS", function () {
		var cert;
        var cms;
		var policies;
		var certFile2012 = "TrustedCrypto2012-256.cer";
		var certFile2012_512 = "TrustedCrypto2012-512.cer";
		var File = "файл6.docx";

        before(function () {
            try {
                fs.statSync(DEFAULT_OUT_PATH).isDirectory();
            } catch (err) {
                fs.mkdirSync(DEFAULT_OUT_PATH);
			}
        })

	it("Sign file with 2012-256 algirithm", function () {
        this.skip();
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile2012, trusted.DataFormat.DER);

		cms = new trusted.cms.SignedData();

        cms.policies = [];

        cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/" + File
        };
        cms.sign(cert);
        cms.save(DEFAULT_OUT_PATH + "/файл6.docx.sig");
    });

	it("Add sign with 2012-512 algorithm", function () {
        this.skip();
		cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile2012_512, trusted.DataFormat.DER);

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_OUT_PATH + "/файл6.docx.sig", trusted.DataFormat.DER);
		cms.policies = [];
        cms.sign(cert);
		cms.save(DEFAULT_OUT_PATH + "/файл6.docx.sig");
	});

});

describe("SIGNERS", function () {
    var cert, certs;
    var cms;
    var signer, signers;
    var File = "two_signs.txt.sig";

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    cert = new trusted.pki.Certificate();
    signer = new trusted.cms.Signer();
    signers = new trusted.cms.SignerCollection();

    cms = new trusted.cms.SignedData();
    cms.load(DEFAULT_RESOURCES_PATH + "/two_signs.txt.sig");
    signers = cms.signers();

    it("Signer Collection length", function () {
        assert.equal(signers.length, 2, "Error signers length");
    });

    it("Signer Collection items", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.signatureAlgorithm), "string", "Bad digest algorithm value of signer");
    });

    it("Signer Certificate", function () {
        signer = signers.items(0);
        cert = signer.certificate;
        assert.equal(typeof (cert.subjectName), "string", "Bad certificate subjectName value of signer");
    });

    it("Signer index", function () {
        signer = signers.items(0);
        var index = signer.index;
        assert.equal(index, 0, "Bad signer's index");
    });

    it("Signer signing time", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.signingTime), "object", "Bad signing time");
    });

    it("Signer Signature Algorithm", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.signatureAlgorithm), "string", "Bad Signature Algorithm");
    });

    it("Signer Signature Digest Algorithm", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.signatureDigestAlgorithm), "string", "Bad Signature Digest Algorithm");
    });

    it("Signer issuer name", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.issuerName), "string", "Bad issuer name");
    });

    it("Signer serial number", function () {
        signer = signers.items(0);
        assert.equal(typeof (signer.serialNumber), "string", "Bad Serial Number");
    });
});


describe("Veryfy signature", function () {
    var cert;
    var cms;
    var signFile_att = "sign2012-256_att.txt.sig";
    var signers;
    var signer, signer1, signer2, signer3;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

    });

    it("Verify valid signature", function () {
        var signers;
        var signer;

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att);
        signers = cms.signers();
        signer = signers.items(0);

        assert.equal(cms.verify() !== false, true, "Signature is not valid");
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer is not valid");
    });

    it("Verify valid detached signature", function () {
        var signers;
        var signer;


        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл4.txt.sig");
        cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл4.txt"
        };
        signers = cms.signers();
        signer = signers.items(0);

        assert.equal(cms.verify() !== false, true, "Signature is not valid");
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer is not valid");

    });

	it("Verify valid two signatures", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/two_signs.txt.sig");
        assert.equal(cms.verify() !== false, true, "Signature is not valid");

    });
	
	it("Verify valid three signatures", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/three_signs.txt.sig");
        assert.equal(cms.verify() !== false, true, "Signature is not valid");

    });

    it("Verify valid one signer", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att);
        signers = cms.signers();
        signer = signers.items(0);

        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer is not valid");
    });

    it("Verify valid two signers", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/two_signs.txt.sig");
        signers = cms.signers();
        signer1 = signers.items(0);
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer1 is not valid");
        signer2 = signers.items(1);
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer2 is not valid");
    });
	
	it("Verify valid three signers", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/three_signs.txt.sig");
        signers = cms.signers();
        signer1 = signers.items(0);
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer1 is not valid");
        signer2 = signers.items(1);
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer2 is not valid");
		signer3 = signers.items(2);
        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer3 is not valid");
    });
	
	it("Verify valid two detached signatures", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/two_signs_det.docx.sig");
		cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл2.docx"
        };
        assert.equal(cms.verify() !== false, true, "Signature is not valid");

    });
	
	it("Verify valid three detached signatures", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/three_signs_det.docx.sig");
		cms.content = {
            type: trusted.cms.SignedDataContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/файл2.docx"
        };
        assert.equal(cms.verify() !== false, true, "Signature is not valid");

    });

    it("Verify valid one signer", function () {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/" + signFile_att);
        signers = cms.signers();
        signer = signers.items(0);

        assert.equal(cms.verify(signer) !== false, true, "Veryfy signature's signer is not valid");
    });

   	it ("Veryfy invalid sign", function() {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл1.xlsx.sig");
        assert.equal(cms.verify() === false, true, "Signature is valid");
    });

	it ("Veryfy changed signed content", function() {
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл2.docx.sig");
        assert.equal(cms.verify() === false, true, "Signature is valid");
    });

	it ("Veryfy invalid certificate's sign", function() {
        var cert = trusted.pki.Certificate();
        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_RESOURCES_PATH + "/файл3.txt.sig");
        cert = cms.certificates(0);
        var res = trusted.utils.Csp.verifyCertificateChain(cert);
        assert.equal(res, false, "Signature is valid");
    });

	it ("Veryfy empty sign", function() {
        cms = new trusted.cms.SignedData();
		assert.throws(function() {
            return cms.load(DEFAULT_RESOURCES_PATH + "/empty1.txt.sig");
        });
    });


});

describe("SIGN ASYNC", function () {
    var certFile = "TrustedCrypto2012-256.cer";
    var plainFile = "файл4.txt";
    var cert;
    var logger;

    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        logger = trusted.common.Logger.start(DEFAULT_OUT_PATH + "/logger.txt", trusted.LoggerLevel.ALL);

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + certFile, trusted.DataFormat.DER);
    });

    after(function () {
        logger.stop();
    });

    var attDet = [false, true];
    var derPem = [true, false];

    derPem.forEach(function (isDer) {
        attDet.forEach(function (isDetached) {
            var caseSuffix = (isDer ? "DER" : "PEM") + "-" + (isDetached ? "detached" : "attached");
            var format = isDer ? trusted.DataFormat.DER : trusted.DataFormat.PEM;
            var result_file_1 = DEFAULT_OUT_PATH + "/Async-01-" + caseSuffix + ".txt.sig";

            describe("SIGN ASYNC: " + caseSuffix, function () {
                var cms;

                it("Sign", function (done) {
                    cms = new trusted.cms.SignedData();

                    cms.policies = isDetached ? ["detached"] : [];

                    cms.content = {
                        type: trusted.cms.SignedDataContentType.url,
                        data: DEFAULT_RESOURCES_PATH + "/" + plainFile
                    };
                    cms.signAsync(cert, done);
                });

                it("Save", function (done) {
                    cms.saveAsync(result_file_1, format, function (msg) {
                        if (msg) {
                            done(msg);
                            return;
                        }

                        assert.strictEqual(fs.existsSync(result_file_1), true, "Sign file not saved");
                        assert.notStrictEqual(fs.statSync(result_file_1).size, 0, "Saved sign is empty");
                        done();
                    });
                });

                it("Import", function (done) {
                    if (isDer) {
                        this.skip();
                    }
                    var sign_data = fs.readFileSync(result_file_1);

                    cms = new trusted.cms.SignedData();
                    cms.importAsync(sign_data, format, done);
                    if (isDetached) {
                        cms.content = {
                            type: trusted.cms.SignedDataContentType.url,
                            data: DEFAULT_RESOURCES_PATH + "/" + plainFile
                        };
                    }
                });

                it("Verify", function (done) {
                    if (isDer) {
                        this.skip();
                    }
                    cms.verifyAsync(function (err, result) {
                        if (err) {
                            done(err);
                            return;
                        }

                        assert.notStrictEqual(result, undefined, "Verify result is undefined");
                        assert.notStrictEqual(result, null, "Verify result is null");
                        done();
                    });
                });

                it("Export", function (done) {
                    if (isDer) {
                        this.skip();
                    }
                    cms.exportAsync(format, function (err, result) {
                        if (err) {
                            done(err);
                            return;
                        }

                        assert.notStrictEqual(result, null, "Exported content is null");
                        if (result) {
                            assert.notStrictEqual(result.length, 0, "Exported content is empty");
                        }
                        done();
                    });
                });

                it("Load", function (done) {
                    cms = new trusted.cms.SignedData();
                    cms.loadAsync(result_file_1, format, function (msg) {
                        if (msg) {
                            done(msg);
                            return;
                        }

                        if (isDetached) {
                            cms.content = {
                                type: trusted.cms.SignedDataContentType.url,
                                data: DEFAULT_RESOURCES_PATH + "/" + plainFile
                            };
                        }
                        done();
                    });
                });

                it("Verify 2", function (done) {
                    cms.verifyAsync(function (err, result) {
                        if (err) {
                            done(err);
                            return;
                        }

                        assert.notStrictEqual(result, undefined, "Verify result is undefined");
                        assert.notStrictEqual(result, null, "Verify result is null");
                        done();
                    });
                });

                it("Add sign", function (done) {
                    cms.signAsync(cert, done);
                });

                it("Save 2", function (done) {
                    var result_file = DEFAULT_OUT_PATH + "/Async-02-" + caseSuffix + ".txt.sig";
                    cms.saveAsync(result_file, format, function (msg) {
                        if (msg) {
                            done(msg);
                            return;
                        }

                        assert.strictEqual(fs.existsSync(result_file), true, "Sign file not saved");
                        assert.notStrictEqual(fs.statSync(result_file).size, 0, "Saved sign is empty");
                        done();
                    });
                });
            });
        });
    });
});

describe("SIGNED_DATA: verify detached by hash value", function () {
    const testData = "Hello world";
    const testSignFormat = trusted.DataFormat.PEM;
    before(function () {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });

    var attrs = [true, false];
    var algs = [
        {
            name: "GOST-2001",
            certFile: "TrustedCrypto2001.cer",
            hashAlgId: trusted.HashAlg.GOST3411_94
        },
        {
            name: "GOST-2012-256",
            certFile: "TrustedCrypto2012-256.cer",
            hashAlgId: trusted.HashAlg.GOST3411_2012_256
        },
        {
            name: "GOST-2012-512",
            certFile: "TrustedCrypto2012-512.cer",
            hashAlgId: trusted.HashAlg.GOST3411_2012_512
        }
    ];

    attrs.forEach(function (useAttrs) {
        algs.forEach(function (curAlg) {
            const signFileName = DEFAULT_OUT_PATH + "/sign-by-hash-" + curAlg.name + (useAttrs ? "" : "-noattrs") + ".sig";

            it(curAlg.name + " " + (useAttrs ? "with" : "NO") + " attributes - verify by hash", function () {
                { // create detached sign
                    var cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/" + curAlg.certFile, trusted.DataFormat.DER);

                    var sd = new trusted.cms.SignedData();
                    if (useAttrs) {
                        sd.policies = ["detached"];
                    } else {
                        sd.policies = ["noAttributes", "detached"];
                    }
                    sd.content = {
                        type: trusted.cms.SignedDataContentType.buffer,
                        data: testData
                    };
                    sd.sign(cert);
                    sd.save(signFileName, testSignFormat);
                }

                var cms = new trusted.cms.SignedData();
                cms.load(signFileName, testSignFormat);
                assert.doesNotThrow(function () {
                    cms.content = {
                        type: trusted.cms.SignedDataContentType.hash,
                        data: {
                            value: trusted.utils.Hash.hashData(
                                curAlg.hashAlgId, Buffer.from(testData)
                            ),
                            alg_id: curAlg.hashAlgId
                        }
                    };
                }, "Error while setting hash as content");

                assert.strictEqual(cms.verify(), true, "Signature must be valid");
                assert.strictEqual(cms.verify(cms.signers().items(0)), true, "Signature must be validby signer");
            });

            it(curAlg.name + " " + (useAttrs ? "with" : "NO") + " attributes - verify by content", function () {
                var cms2 = new trusted.cms.SignedData();
                cms2.load(signFileName, testSignFormat);
                cms2.content = {
                    type: trusted.cms.SignedDataContentType.buffer,
                    data: testData
                };

                assert.strictEqual(cms2.verify(), true, "Signature must be valid");
                assert.strictEqual(cms2.verify(cms2.signers().items(0)), true, "Signature must be validby signer");
            });

            it(curAlg.name + " " + (useAttrs ? "with" : "NO") + " attributes - verify by wrong hash value", function () {
                var cms = new trusted.cms.SignedData();
                cms.load(signFileName, testSignFormat);
                assert.doesNotThrow(function () {
                    cms.content = {
                        type: trusted.cms.SignedDataContentType.hash,
                        data: {
                            value: trusted.utils.Hash.hashData(
                                curAlg.hashAlgId, Buffer.from(testData + " spoiler")
                            ),
                            alg_id: curAlg.hashAlgId
                        }
                    };
                }, "Error while setting hash as content");

                assert.strictEqual(cms.verify(), false, "Signature must be invalid");
                assert.strictEqual(cms.verify(cms.signers().items(0)), false, "Signature must be invalid (by signer)");
            });
        });
    });

    describe("SIGNED_DATA: verify detached by hash value - side effects tests", function () {
        var signCadesDetached = DEFAULT_RESOURCES_PATH + "/signCadesDetached.txt.sig";

        it("Verify signature without any content", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/sign-by-hash-GOST-2012-256.sig", testSignFormat);
            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify();
            }, "Verification of signature without any content must throw exception");
        });

        it("Verify signature without any content by signer", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(DEFAULT_OUT_PATH + "/sign-by-hash-GOST-2012-256.sig", testSignFormat);
            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify(cms.signers().items(0));
            }, "Verification of signature without any content must throw exception");
        });

        it("Verify CAdES with content", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            cms.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "detached content"
            };
            assert.strictEqual(cms.verify(), true, "Signature must be valid");
        });

        it("Verify CAdES with content by signer", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            cms.content = {
                type: trusted.cms.SignedDataContentType.buffer,
                data: "detached content"
            };
            assert.strictEqual(cms.verify(cms.signers().items(0)), true, "Signature must be valid");
        });

        it("Verify CAdES with hash as content", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            assert.doesNotThrow(function () {
                cms.content = {
                    type: trusted.cms.SignedDataContentType.hash,
                    data: {
                        value: trusted.utils.Hash.hashData(
                            trusted.HashAlg.GOST3411_2012_256, Buffer.from("detached content")
                        ),
                        alg_id: trusted.HashAlg.GOST3411_2012_256
                    }
                };
            }, "Error while setting hash as content");

            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify();
            }, "Verification of CAdES by hash is not supported (must throw exception)");
        });

        it("Verify CAdES with hash as content by signer", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            assert.doesNotThrow(function () {
                cms.content = {
                    type: trusted.cms.SignedDataContentType.hash,
                    data: {
                        value: trusted.utils.Hash.hashData(
                            trusted.HashAlg.GOST3411_2012_256, Buffer.from("detached content")
                        ),
                        alg_id: trusted.HashAlg.GOST3411_2012_256
                    }
                };
            }, "Error while setting hash as content");

            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify(cms.signers().items(0));
            }, "Verification of CAdES by hash is not supported (must throw exception)");
        });

        it("Verify CAdES without any content", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify();
            }, "Verification of CAdES without any content must throw exception");
        });

        it("Verify CAdES without any content by signer", function () {
            var cms = new trusted.cms.SignedData();
            cms.load(signCadesDetached, trusted.DataFormat.DER);
            var verifyResult = false;
            assert.throws(function () {
                verifyResult = cms.verify(cms.signers().items(0));
            }, "Verification of CAdES without any content must throw exception");
        });
    });
});
