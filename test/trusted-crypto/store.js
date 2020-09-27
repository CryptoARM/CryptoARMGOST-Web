"use strict";

var assert = require("assert");
var os = require("os");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var DEFAULT_RESOURCES_PATH = "test/resources";
var CPROCSP = 0;

/**
* Check file exists
* @param  {string} filePath Path to file
* @returns {boolean} file exists?
*/
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

describe("Store", function () {
    var store;
    var providerSystem, providerMicrosoft, providerCryptopro;
    var certWithKey;
    var uri;
    var osType = os.type();

    it("init", function () {
        providerSystem = new trusted.pkistore.ProviderCryptopro();
        assert.equal(providerSystem !== null, true);

        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
        assert.equal(store !== null, true);

        store.addProvider(providerSystem.handle);
    });

    it("add pki objects", function () {
        var cert, newCert;
        var crl, newCrl;

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test_store.cer", trusted.DataFormat.PEM);
        crl = trusted.pki.CRL.load(DEFAULT_RESOURCES_PATH + "/crl2012.crl");

        store.addCert(providerSystem.handle, "ADDRESSBOOK", cert);
        store.addCrl(providerSystem.handle, "CA", crl);

        store.deleteCert(providerSystem.handle, "ADDRESSBOOK", cert);
        store.deleteCrl(providerSystem.handle, "CA", crl);
    });

    it("find", function () {
        var item;
        var cert;

        var certs = store.find({
            type: ["CERTIFICATE"],
            category: ["ADDRESSBOOK"]
        });

        var crls = store.find({
            type: ["CRL"]
        });

        for (var i = 0; i < certs.length; i++) {
            item = certs[i];
            if (item.key) {
                cert = store.getItem(item);
                assert.equal(cert.subjectName.length > 0, true);
            }
        }

        //     for (i = 0; i < certs.length; i++) {
        //         item = certs[i];
        //         assert.equal(item.type, "CERTIFICATE");

        //         if (item.provider === "MICROSOFT") {
        //             cert = store.getItem(item);
        //             assert.equal(cert.subjectName.length > 0, true);
        //             assert.equal(typeof (providerMicrosoft.hasPrivateKey(cert)), "boolean", "Bad hasPrivateKey value type");
        //             break;
        //         }
        //     }

        //     assert.equal(!!certWithKey, true, "Error get certificate with key");

        //     var key = store.findKey({
        //         type: ["CERTIFICATE"],
        //         provider: ["SYSTEM"],
        //         category: ["MY"],
        //         hash: certWithKey.thumbprint.toString("hex")
        //     });

        //     assert.equal(!!key, true, "Error get private key");
    });

    // it("json", function() {
    //     var items;
    //     var exportPKI;

    //     var items = store.find({
    //         type: ["CERTIFICATE"],
    //         category: ["MY"]
    //     });
    //     store.cash.import(items);
    //     exportPKI = store.cash.export();
    //     assert.equal(exportPKI.length > 0, true);
    // });

    // it("Object to PkiItem", function() {
    //     var item;

    //     item = providerSystem.objectToPkiItem(uri);
    //     assert.equal(item !== null, true);
    // });

});
