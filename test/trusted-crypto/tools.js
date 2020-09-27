"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("TOOLS", function () {
    var module;

    module = new trusted.utils.Tools();

    describe("stringToBase64", function () {
        var strBase64 = module.stringToBase64("Hello World", 1);
        var strBase64_ = strBase64.replace(/\r?\n/g, "")
        it("Hello World" + " -> " + strBase64_, function () {
            assert.equal(strBase64_, "SGVsbG8gV29ybGQ=", "Convertion to BASE64 no correct");
        });
    });

    describe("stringFromBase64", function () {
        var strDer = module.stringFromBase64("SGVsbG8gV29ybGQ=", 7);
        it("SGVsbG8gV29ybGQ=" + " -> " + strDer, function () {
            assert.equal(strDer, "Hello World", "Convertion from BASE64 no correct");
        });
    });

});
