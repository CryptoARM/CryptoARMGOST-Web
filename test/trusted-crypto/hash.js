"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

var hash_algs = [
    {
        id: trusted.HashAlg.GOST3411_94,
        name: "GOST3411_94",
        testVal1: {
            hex: "16DA9BC02CE5307822F47A3108D33852562363582A2935C0043CCA27FC024F53",
            base64: "FtqbwCzlMHgi9HoxCNM4UlYjY1gqKTXABDzKJ/wCT1M="
        },
        testVal2: {
            hex: "89F38DACFBE2B7F5E9B1BE5D7E6436C016814169BB21003B9C56D7C39370C9F6",
            base64: "ifONrPvit/Xpsb5dfmQ2wBaBQWm7IQA7nFbXw5NwyfY="
        },
        testVal3: {
            hex: "2344A0A62ED82883614A5B3A25363A90E27EF9042E75C5CA493F9A3BEFD94BC7",
            base64: "I0Sgpi7YKINhSls6JTY6kOJ++QQudcXKST+aO+/ZS8c="
        }
    },
    {
        id: trusted.HashAlg.GOST3411_2012_256,
        name: "GOST3411_2012_256",
        testVal1: {
            hex: "C130B4CB082AB0B242A3CD8AA30EBC1C63CBE9B90E1D925103D565E0B0F0031E",
            base64: "wTC0ywgqsLJCo82Kow68HGPL6bkOHZJRA9Vl4LDwAx4="
        },
        testVal2: {
            hex: "F33A8FA0F86B9281AD8C5A4731256E5E0C5B9648D3D4BDE39192B73ED5F05DCF",
            base64: "8zqPoPhrkoGtjFpHMSVuXgxblkjT1L3jkZK3PtXwXc8="
        },
        testVal3: {
            hex: "54C743934EC25C75B417E2532091E9963394DE01FA3AFCC9D4240954691421C7",
            base64: "VMdDk07CXHW0F+JTIJHpljOU3gH6OvzJ1CQJVGkUIcc="
        }
    },
    {
        id: trusted.HashAlg.GOST3411_2012_512,
        name: "GOST3411_2012_512",
        testVal1: {
            hex: "B1821FBD43394CA00F8114BA9FAE108767B98BDD5A02F354C071DDF3E8BEC78F1F4121D8A4FD30B7DEDDB1853807BA06E09A85FD29119594659D590512A0F728",
            base64: "sYIfvUM5TKAPgRS6n64Qh2e5i91aAvNUwHHd8+i+x48fQSHYpP0wt97dsYU4B7oG4JqF/SkRlZRlnVkFEqD3KA=="
        },
        testVal2: {
            hex: "4BB1191745E48C63F5236038B36021E23FE9858118C0B3566D269354578465B93777DBD86668558F2F142A57FF4B25F4705408827852E0D7B631D291150CF6D1",
            base64: "S7EZF0XkjGP1I2A4s2Ah4j/phYEYwLNWbSaTVFeEZbk3d9vYZmhVjy8UKlf/SyX0cFQIgnhS4Ne2MdKRFQz20Q=="
        },
        testVal3: {
            hex: "342A4A80993D1711AF7BF7400EB21F8583332BC9AEA1498AD483E6E9C172BE3FE53F27994C3646FBEC4685E9F101698DE19F7BF09831222A0D454CE697410C12",
            base64: "NCpKgJk9FxGve/dADrIfhYMzK8muoUmK1IPm6cFyvj/lPyeZTDZG++xGhenxAWmN4Z978JgxIioNRUzml0EMEg=="
        }
    }
];

var hashValue = undefined;
hash_algs.forEach(function (hash_alg) {
    describe("HASH " + hash_alg.name, function () {
        var hash;
        hashValue = undefined;

        it("Initialize object", function () {
            assert.doesNotThrow(function () {
                hash = new trusted.utils.Hash(hash_alg.id);
            }, "Error while creating hash object");
            assert.notStrictEqual(hash, undefined, "Hash object is undefined");
            assert.notStrictEqual(hash, null, "Hash object is null");
        });

        it("Add data", function () {
            var dataBuf01 = Buffer.from("Data part 01");
            assert.doesNotThrow(function () {
                hash.addData(dataBuf01);
            }, "Error while adding first part of data");

            var dataBuf02 = Buffer.from("Data part 02");
            assert.doesNotThrow(function () {
                hash.addData(dataBuf02);
            }, "Error while adding second part of data");
        });

        it("Get value", function () {
            assert.doesNotThrow(function () {
                hashValue = hash.getValue();
            }, "Error while obtaining hash value (default type)");

            assert.notStrictEqual(hashValue, undefined, "Unable to get hash value - result is undefined");
            assert.notStrictEqual(hashValue, null, "Unable to get hash value - result is null");
        });

        verifyValue("consequental calculation", hash_alg.testVal1);

        it("Add data after finalizing", function () {
            var dataBuf03 = Buffer.from("Data part 03");
            assert.throws(function () {
                hash.addData(dataBuf03);
            }, "AddData must not works after value recieving");
        });

        var sync_async = [false, true];
        sync_async.forEach(function (isAsync) {
            var asyncSuffix = isAsync ? " - ASYNC" : "";

            if (isAsync) {
                it("Hash data from buffer - ASYNC", function (done) {
                    hashValue = undefined;
                    var dataBuf04 = Buffer.from("Test data from buffer");
                    assert.doesNotThrow(function () {
                        trusted.utils.Hash.hashDataAsync(hash_alg.id, dataBuf04, function (error, result) {
                            if (error) {
                                done(error);
                                return;
                            }

                            hashValue = result;
                            assert.notStrictEqual(hashValue, undefined, "Unable to get hash value - result is undefined");
                            assert.notStrictEqual(hashValue, null, "Unable to get hash value - result is null");
                            done();
                        });
                    });
                });
            } else {
                it("Hash data from buffer", function () {
                    hashValue = undefined;
                    assert.doesNotThrow(function () {
                        var dataBuf04 = Buffer.from("Test data from buffer");
                        hashValue = trusted.utils.Hash.hashData(hash_alg.id, dataBuf04);
                    }, "Error while hashing data from buffer");

                    assert.notStrictEqual(hashValue, undefined, "Unable to get hash value - result is undefined");
                    assert.notStrictEqual(hashValue, null, "Unable to get hash value - result is null");
                });
            }

            verifyValue("calculation from buffer" + asyncSuffix, hash_alg.testVal2);

            if (isAsync) {
                it("Hash data from file - ASYNC", function (done) {
                    hashValue = undefined;
                    assert.doesNotThrow(function () {
                        trusted.utils.Hash.hashDataAsync(hash_alg.id, DEFAULT_RESOURCES_PATH + "/131072.txt", function (error, result) {
                            if (error) {
                                done(error);
                                return;
                            }

                            hashValue = result;
                            assert.notStrictEqual(hashValue, undefined, "Unable to get hash value - result is undefined");
                            assert.notStrictEqual(hashValue, null, "Unable to get hash value - result is null");
                            done();
                        });
                    });
                });
            } else {
                it("Hash data from file", function () {
                    hashValue = undefined;
                    assert.doesNotThrow(function () {
                        hashValue = trusted.utils.Hash.hashData(hash_alg.id, DEFAULT_RESOURCES_PATH + "/131072.txt");
                    }, "Error while hashing data from buffer");

                    assert.notStrictEqual(hashValue, undefined, "Unable to get hash value - result is undefined");
                    assert.notStrictEqual(hashValue, null, "Unable to get hash value - result is null");
                });
            }

            verifyValue("calculation from file" + asyncSuffix, hash_alg.testVal3);
        });
    });
});

function verifyValue(testSuffix, contolValueObject) {
    it("Check returned value type - " + testSuffix, function () {
        assert.strictEqual(typeof (hashValue), "object", "Returned value must be in buffer (object check failed)");
        assert.strictEqual(Buffer.isBuffer(hashValue), true, "Returned value must be in buffer (isBuffer check failed)");
    });

    it("Check returned value - " + testSuffix, function () {
        assert.notStrictEqual(hashValue.length, 0, "Unable to get hash value - result is empty");

        assert.strictEqual(hashValue.toString("hex").toUpperCase(), contolValueObject.hex.toUpperCase(), "Wrong hex value");
        assert.strictEqual(hashValue.toString("base64"), contolValueObject.base64, "Wrong BASE64 value");
    });
}
