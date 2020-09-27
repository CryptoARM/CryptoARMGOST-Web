"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("MODULE", function () {
    var module;

    module = new trusted.utils.ModuleInfo;

    describe("Name", function () {

        it("-> " + module.name, function () {
            assert.equal(typeof (module.name), "string", "Bad name");
        });
    });

    describe("Version", function () {

        it("-> " + module.version, function () {
            assert.equal(typeof (module.version), "string", "Bad version");
        });
    });
});
