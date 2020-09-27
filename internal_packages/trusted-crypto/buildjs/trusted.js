"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var trusted;
(function (trusted) {
    /**
     *
     * @export
     * @enum {number}
     */
    var EncryptAlg;
    (function (EncryptAlg) {
        EncryptAlg[EncryptAlg["GOST_28147"] = 0] = "GOST_28147";
        EncryptAlg[EncryptAlg["GOST_R3412_2015_M"] = 1] = "GOST_R3412_2015_M";
        EncryptAlg[EncryptAlg["GOST_R3412_2015_K"] = 2] = "GOST_R3412_2015_K";
        EncryptAlg[EncryptAlg["RC2"] = 3] = "RC2";
        EncryptAlg[EncryptAlg["RC4"] = 4] = "RC4";
        EncryptAlg[EncryptAlg["DES"] = 5] = "DES";
        EncryptAlg[EncryptAlg["DES3"] = 6] = "DES3";
        EncryptAlg[EncryptAlg["AES_128"] = 7] = "AES_128";
        EncryptAlg[EncryptAlg["AES_192"] = 8] = "AES_192";
        EncryptAlg[EncryptAlg["AES_256"] = 9] = "AES_256";
    })(EncryptAlg = trusted.EncryptAlg || (trusted.EncryptAlg = {}));
})(trusted || (trusted = {}));
var trusted;
(function (trusted) {
    /**
     *
     * @export
     * @enum {number}
     */
    var HashAlg;
    (function (HashAlg) {
        HashAlg[HashAlg["GOST3411_94"] = 0] = "GOST3411_94";
        HashAlg[HashAlg["GOST3411_2012_256"] = 1] = "GOST3411_2012_256";
        HashAlg[HashAlg["GOST3411_2012_512"] = 2] = "GOST3411_2012_512";
    })(HashAlg = trusted.HashAlg || (trusted.HashAlg = {}));
})(trusted || (trusted = {}));
var trusted;
(function (trusted) {
    /**
     *
     * @export
     * @enum {number}
     */
    var DataFormat;
    (function (DataFormat) {
        DataFormat[DataFormat["DER"] = 0] = "DER";
        DataFormat[DataFormat["PEM"] = 1] = "PEM";
    })(DataFormat = trusted.DataFormat || (trusted.DataFormat = {}));
})(trusted || (trusted = {}));
/// <reference types="node" />
var trusted;
(function (trusted) {
    var BaseObject = /** @class */ (function () {
        function BaseObject() {
        }
        BaseObject.wrap = function (obj) {
            if (!obj) {
                throw TypeError("BaseObjectCheck::Wrong incoming object for wrap function");
            }
            var newObj = new this();
            newObj.handle = obj;
            return newObj;
        };
        return BaseObject;
    }());
    trusted.BaseObject = BaseObject;
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var cms;
    (function (cms) {
        /**
         * Wrap CMS_SignerInfo
         *
         * @export
         * @class Signer
         * @extends {BaseObject<native.CMS.Signer>}
         */
        var Signer = /** @class */ (function (_super) {
            __extends(Signer, _super);
            /**
             * Creates an instance of Signer.
             *
             * @param {native.CMS.Signer} handle
             *
             * @memberOf Signer
             */
            function Signer(nativeHandle) {
                var _this = _super.call(this) || this;
                if (nativeHandle instanceof native.CMS.Signer) {
                    _this.handle = nativeHandle;
                }
                else {
                    _this.handle = new native.CMS.Signer();
                }
                return _this;
            }
            Object.defineProperty(Signer.prototype, "certificate", {
                /**
                 * Return signer certificate
                 *
                 * @type {Certificate}
                 * @memberOf Signer
                 */
                get: function () {
                    var cert = this.handle.getCertificate();
                    if (cert) {
                        return trusted.pki.Certificate.wrap(cert);
                    }
                    else {
                        return undefined;
                    }
                },
                /**
                 * Set signer certificate
                 * Error if cert no signer
                 *
                 * @param cert Certificate
                 *
                 * @memberOf Signer
                 */
                set: function (cert) {
                    this.handle.setCertificate(cert.handle);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "index", {
                /**
                 * Return Index
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.getIndex();
                },
                /**
                 * Set index certificate
                 *
                 * @param ind string
                 *
                 * @memberOf Signer
                 */
                set: function (ind) {
                    this.handle.setIndex(ind);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "signingTime", {
                /**
                 * Return signing time from signed attributes
                 *
                 * @readonly
                 * @type {Date}
                 * @memberof Signer
                 */
                get: function () {
                    var strDate = this.handle.getSigningTime();
                    if (!strDate.length) {
                        return undefined;
                    }
                    return new Date(strDate);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "signatureAlgorithm", {
                /**
                * Return signature algorithm
                *
                * @readonly
                * @type {string}
                * @memberOf Signer
                */
                get: function () {
                    return this.handle.getSignatureAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "signatureDigestAlgorithm", {
                /**
                 * Return signature digest algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.getDigestAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "issuerName", {
                /**
                 * Return issuer name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.getIssuerName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "serialNumber", {
                /**
                 * Return serial number of certificate
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.getSerialNumber();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Return time stamp of specified type
             *
             * @type {TSP}
             * @memberOf Signer
             */
            Signer.prototype.timestamp = function (tspType) {
                if (typeof tspType !== "number")
                    throw new TypeError("Signer::signParams: Wrong input param");
                var resultTsp = undefined;
                var timeStamp = this.handle.timestamp(tspType);
                if (timeStamp !== undefined)
                    resultTsp = new trusted.pki.TSP(timeStamp);
                return resultTsp;
            };
            /**
             * Verifyes time stamp of specified type from signer
             *
             * @type {boolean}
             * @memberOf Signer
             */
            Signer.prototype.verifyTimestamp = function (tspType) {
                if (typeof tspType !== "number")
                    throw new TypeError("Signer::signParams: Wrong input param");
                return this.handle.verifyTimestamp(tspType);
            };
            Object.defineProperty(Signer.prototype, "isCades", {
                /**
                 * Identify if signer is CAdES or not
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.isCades();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "certificateValues", {
                /**
                 * For CAdES returns collection of certificates from certificateValues attribute
                 *
                 * @type {CertificateCollection}
                 * @memberOf Signer
                 */
                get: function () {
                    var certVals = this.handle.certificateValues();
                    if (certVals === undefined) {
                        return undefined;
                    }
                    return trusted.pki.Certificate.wrap(certVals);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "revocationValues", {
                /**
                 * For CAdES returns array of buffers with encoded revocation values (OCSP response or CRL)
                 *
                 * @readonly
                 * @type {Buffer[]}
                 * @memberOf Signer
                 */
                get: function () {
                    return this.handle.revocationValues();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Signer.prototype, "ocspResp", {
                /**
                 * For CAdES returns OCSP response
                 *
                 * @readonly
                 * @type {OCSP}
                 * @memberOf Signer
                 */
                get: function () {
                    var resultOcsp = undefined;
                    var resp = this.handle.ocspResp();
                    if (resp !== undefined)
                        resultOcsp = new trusted.pki.OCSP(resp);
                    return resultOcsp;
                },
                enumerable: true,
                configurable: true
            });
            return Signer;
        }(trusted.BaseObject));
        cms.Signer = Signer;
    })(cms = trusted.cms || (trusted.cms = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var cms;
    (function (cms) {
        /**
         * Collection of Signer
         *
         * @export
         * @class SignerCollection
         * @extends {BaseObject<native.CMS.SignerCollection>}
         * @implements {Collection.ICollection}
         */
        var SignerCollection = /** @class */ (function (_super) {
            __extends(SignerCollection, _super);
            /**
             * Creates an instance of SignerCollection.
             *
             * @param {native.CMS.SignerCollection} nativeHandle
             *
             * @memberOf SignerCollection
             */
            function SignerCollection(nativeHandle) {
                var _this = _super.call(this) || this;
                _this.handle = nativeHandle;
                return _this;
            }
            /**
             * Return element by index from collection
             *
             * @param {number} index
             * @returns {Signer}
             *
             * @memberOf SignerCollection
             */
            SignerCollection.prototype.items = function (index) {
                return new cms.Signer(this.handle.items(index));
            };
            Object.defineProperty(SignerCollection.prototype, "length", {
                /**
                 * Return collection length
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf SignerCollection
                 */
                get: function () {
                    return this.handle.length();
                },
                enumerable: true,
                configurable: true
            });
            return SignerCollection;
        }(trusted.BaseObject));
        cms.SignerCollection = SignerCollection;
    })(cms = trusted.cms || (trusted.cms = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
/* tslint:disable:no-bitwise */
var trusted;
(function (trusted) {
    var cms;
    (function (cms_1) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.DER;
        var SignedDataContentType;
        (function (SignedDataContentType) {
            SignedDataContentType[SignedDataContentType["url"] = 0] = "url";
            SignedDataContentType[SignedDataContentType["buffer"] = 1] = "buffer";
            SignedDataContentType[SignedDataContentType["hash"] = 2] = "hash";
        })(SignedDataContentType = cms_1.SignedDataContentType || (cms_1.SignedDataContentType = {}));
        /**
         * Signed data policy
         *
         * @enum {number}
         */
        var SignedDataPolicy;
        (function (SignedDataPolicy) {
            // text = 0x1,
            // noCertificates = 0x2,
            // noContentVerify = 0x4,
            // noAttributeVerify = 0x8,
            // noSignatures = noAttributeVerify | noContentVerify,
            // noIntern = 0x10,
            // noSignerCertificateVerify = 0x20,
            // noVerify = 0x20,
            SignedDataPolicy[SignedDataPolicy["detached"] = 4] = "detached";
            // binary = 0x80,
            SignedDataPolicy[SignedDataPolicy["noAttributes"] = 512] = "noAttributes";
            // noSmimeCap = 0x200,
            // noOldMimeType = 0x400,
            // crlFEOL = 0x800,
            // stream = 0x1000,
            // noCrtl = 0x2000,
            // partial = 0x4000,
            // reuseDigest = 0x8000,
            // useKeyId = 0x10000,
            // debugDecrypt = 0x20000,
        })(SignedDataPolicy || (SignedDataPolicy = {}));
        /**
         * Get name
         *
         * @param {*} e
         * @param {string} name
         * @returns {*}
         */
        function EnumGetName(e, name) {
            "use strict";
            for (var i in e) {
                if (i.toString().toLowerCase() === name.toLowerCase()) {
                    return { name: i, value: e[i] };
                }
            }
            return undefined;
        }
        var StampType;
        (function (StampType) {
            StampType[StampType["stContent"] = 1] = "stContent";
            StampType[StampType["stSignature"] = 2] = "stSignature";
            StampType[StampType["stEscStamp"] = 4] = "stEscStamp";
        })(StampType = cms_1.StampType || (cms_1.StampType = {}));
        var TimestampParams = /** @class */ (function (_super) {
            __extends(TimestampParams, _super);
            /**
             * Creates an instance of TimestampParams.
             *
             *
             * @memberOf TimestampParams
             */
            function TimestampParams() {
                var _this = _super.call(this) || this;
                _this.handle = new native.CMS.TimestampParams();
                return _this;
            }
            Object.defineProperty(TimestampParams.prototype, "stampType", {
                /**
                 * Return time stamp type
                 *
                 * @type {StampType}
                 * @memberOf TimestampParams
                 */
                get: function () {
                    return this.handle.getStampType();
                },
                /**
                 * Set time stamp type
                 *
                 *
                 * @memberOf TimestampParams
                 */
                set: function (stmp) {
                    this.handle.setStampType(stmp);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TimestampParams.prototype, "connSettings", {
                /**
                 * Return connection settings for time stamp service
                 *
                 * @type {trusted.utils.ConnectionSettings}
                 * @memberOf TimestampParams
                 */
                get: function () {
                    var connSett = new trusted.utils.ConnectionSettings();
                    connSett.handle = this.handle.getConnSettings();
                    return connSett;
                },
                /**
                 * Set connection settings for time stamp service
                 *
                 *
                 * @memberOf TimestampParams
                 */
                set: function (connSett) {
                    this.handle.setConnSettings(connSett.handle);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TimestampParams.prototype, "tspHashAlg", {
                /**
                 * Return time stamp hash algorithm OID
                 *
                 * @type {String}
                 * @memberOf TimestampParams
                 */
                get: function () {
                    return this.handle.getTspHashAlg();
                },
                /**
                 * Set time stamp hash algorithm OID
                 *
                 *
                 * @memberOf TimestampParams
                 */
                set: function (hashAlg) {
                    this.handle.setTspHashAlg(hashAlg);
                },
                enumerable: true,
                configurable: true
            });
            return TimestampParams;
        }(trusted.BaseObject));
        cms_1.TimestampParams = TimestampParams;
        /**
        * Supported CAdES types
        *
        * @enum {number}
        */
        var CadesType;
        (function (CadesType) {
            CadesType[CadesType["ctCadesXLT1"] = 1] = "ctCadesXLT1";
            //ctCadesT = 2,
            //stCadesA = 3
        })(CadesType = cms_1.CadesType || (cms_1.CadesType = {}));
        var CadesParams = /** @class */ (function (_super) {
            __extends(CadesParams, _super);
            /**
             * Creates an instance of TimestampParams.
             *
             *
             * @memberOf CadesParams
             */
            function CadesParams() {
                var _this = _super.call(this) || this;
                _this.handle = new native.CMS.CadesParams();
                return _this;
            }
            Object.defineProperty(CadesParams.prototype, "cadesType", {
                /**
                 * Return time stamp type
                 *
                 * @type {CadesType}
                 * @memberOf CadesParams
                 */
                get: function () {
                    return this.handle.getCadesType();
                },
                /**
                 * Set time stamp type
                 *
                 *
                 * @memberOf CadesParams
                 */
                set: function (signType) {
                    this.handle.setCadesType(signType);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CadesParams.prototype, "connSettings", {
                /**
                 * Return connection settings for time stamp service
                 *
                 * @type {trusted.utils.ConnectionSettings}
                 * @memberOf CadesParams
                 */
                get: function () {
                    var connSett = new trusted.utils.ConnectionSettings();
                    connSett.handle = this.handle.getConnSettings();
                    return connSett;
                },
                /**
                 * Set connection settings for time stamp service
                 *
                 *
                 * @memberOf CadesParams
                 */
                set: function (connSett) {
                    this.handle.setConnSettings(connSett.handle);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CadesParams.prototype, "tspHashAlg", {
                /**
                 * Return time stamp hash algorithm OID
                 *
                 * @type {String}
                 * @memberOf CadesParams
                 */
                get: function () {
                    return this.handle.getTspHashAlg();
                },
                /**
                 * Set time stamp hash algorithm OID
                 *
                 *
                 * @memberOf CadesParams
                 */
                set: function (hashAlg) {
                    this.handle.setTspHashAlg(hashAlg);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CadesParams.prototype, "ocspSettings", {
                /**
                 * Return connection settings for OCSP service
                 *
                 * @type {trusted.utils.ConnectionSettings}
                 * @memberOf CadesParams
                 */
                get: function () {
                    var connSett = new trusted.utils.ConnectionSettings();
                    connSett.handle = this.handle.getOcspSettings();
                    return connSett;
                },
                /**
                 * Set connection settings for time stamp service
                 *
                 *
                 * @memberOf CadesParams
                 */
                set: function (connSett) {
                    this.handle.setOcspSettings(connSett.handle);
                },
                enumerable: true,
                configurable: true
            });
            return CadesParams;
        }(trusted.BaseObject));
        cms_1.CadesParams = CadesParams;
        /**
         * Wrap CMS_ContentInfo
         *
         * @export
         * @class SignedData
         * @extends {BaseObject<native.CMS.SignedData>}
         */
        var SignedData = /** @class */ (function (_super) {
            __extends(SignedData, _super);
            /**
             * Creates an instance of SignedData.
             *
             *
             * @memberOf SignedData
             */
            function SignedData() {
                var _this = _super.call(this) || this;
                _this.prContent = undefined;
                _this.handle = new native.CMS.SignedData();
                return _this;
            }
            /**
             * Load signed data from file location
             *
             * @static
             * @param {string} filename File location
             * @param {DataFormat} [format] PEM | DER
             * @returns {SignedData}
             *
             * @memberOf SignedData
             */
            SignedData.load = function (filename, format) {
                var cms = new SignedData();
                cms.handle.load(filename, format);
                return cms;
            };
            /**
             * Load signed data from memory
             *
             * @static
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
             * @returns {SignedData}
             *
             * @memberOf SignedData
             */
            SignedData.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                var cms = new SignedData();
                cms.handle.import(buffer, format);
                return cms;
            };
            Object.defineProperty(SignedData.prototype, "content", {
                /**
                 * Return content of signed data
                 *
                 * @type {ISignedDataContent}
                 * @memberOf SignedData
                 */
                get: function () {
                    if (!this.prContent && !this.isDetached()) {
                        // Извлечь содержимое из подписи
                        var buf = this.handle.getContent();
                        this.prContent = {
                            data: buf,
                            type: SignedDataContentType.buffer,
                        };
                    }
                    return this.prContent;
                },
                /**
                 * Set content v to signed data
                 *
                 *
                 * @memberOf SignedData
                 */
                set: function (v) {
                    var data;
                    if (v.type === SignedDataContentType.url) {
                        data = v.data.toString();
                    }
                    else if (v.type === SignedDataContentType.buffer) {
                        data = Buffer.from(v.data);
                    }
                    if (v.type === SignedDataContentType.hash) {
                        var hash = v.data;
                        if (!hash.value) {
                            throw new TypeError("SignedData::content: hash value is not specified for 'hash' content type");
                        }
                        this.handle.setContentAsHash(hash.value, hash.alg_id);
                    }
                    else {
                        this.handle.setContent(data);
                    }
                    this.prContent = v;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(SignedData.prototype, "policies", {
                /**
                * Return sign policys
                *
                * @type {Array<string>}
                * @memberOf SignedData
                */
                get: function () {
                    var p = new Array();
                    var flags = this.handle.getFlags();
                    for (var i in SignedDataPolicy) {
                        if (+i & flags) {
                            p.push(SignedDataPolicy[i]);
                        }
                    }
                    return p;
                },
                /**
                * Set sign policies
                *
                *
                * @memberOf SignedData
                */
                set: function (v) {
                    var flags = 0;
                    for (var _i = 0, v_1 = v; _i < v_1.length; _i++) {
                        var item = v_1[_i];
                        var flag = EnumGetName(SignedDataPolicy, item);
                        if (flag) {
                            flags |= +flag.value;
                        }
                    }
                    this.handle.setFlags(flags);
                },
                enumerable: true,
                configurable: true
            });
            /**
             *  Free signed content
             *
             * @returns {void}
             * @memberof SignedData
             */
            SignedData.prototype.freeContent = function () {
                return this.handle.freeContent();
            };
            /**
             * Return true if sign detached
             *
             * @returns {boolean}
             *
             * @memberOf SignedData
             */
            SignedData.prototype.isDetached = function () {
                return this.handle.isDetached();
            };
            /**
             * Return certificates collection or certificate by index (if request)
             *
             * @param {number} [index]
             * @returns {*}
             *
             * @memberOf SignedData
             */
            SignedData.prototype.certificates = function (index) {
                var certs = new trusted.pki.CertificateCollection(this.handle.getCertificates());
                if (index !== undefined) {
                    return certs.items(index);
                }
                return certs;
            };
            /**
            * Return signers collection or signer by index (if request)
            *
            * @param {number} [index]
            * @returns {*}
            *
            * @memberOf SignedData
            */
            SignedData.prototype.signers = function (index) {
                var signers = new cms_1.SignerCollection(this.handle.getSigners());
                if (index !== undefined) {
                    return signers.items(index);
                }
                return signers;
            };
            /**
             * Load sign from file location
             *
             * @param {string} filename File location
             * @param {DataFormat} [format] PEM | DER
             *
             * @memberOf SignedData
             */
            SignedData.prototype.load = function (filename, format) {
                this.handle.load(filename, format);
            };
            /**
             * Load sign asynchronously from file location
             *
             * @param {string} filename File location
             * @param {DataFormat} [format] PEM | DER
             * @param {(message: string) => void} done Done callback
             *
             * @memberOf SignedData
             */
            SignedData.prototype.loadAsync = function (filename, format, done) {
                this.handle.loadAsync(filename, format, done);
            };
            /**
             * Load sign from memory
             *
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             *
             * @memberOf SignedData
             */
            SignedData.prototype.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.import(buffer, format);
            };
            /**
             * Load sign asynchronously from memory
             *
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             * @param {(message: string) => void} done Done callback
             *
             * @memberOf SignedData
             */
            SignedData.prototype.importAsync = function (buffer, format, done) {
                this.handle.importAsync(buffer, format, done);
            };
            /**
             * Save sign to memory
             *
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             * @returns {Buffer}
             *
             * @memberOf SignedData
             */
            SignedData.prototype.export = function (format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                return this.handle.export(format);
            };
            /**
             * Save sign to memory asynchronously
             *
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             * @returns {Buffer}
             * @param {(error: string, result: Buffer) => void} done Callback to get returned value or error
             *
             * @memberOf SignedData
             */
            SignedData.prototype.exportAsync = function (format, done) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.exportAsync(format, done);
            };
            /**
             * Write sign to file
             *
             * @param {string} filename File location
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             *
             * @memberOf SignedData
             */
            SignedData.prototype.save = function (filename, format) {
                this.handle.save(filename, format);
            };
            /**
             * Write sign to file asynchronously
             *
             * @param {string} filename File location
             * @param {DataFormat} format PEM | DER
             * @param {(message: string)=>void} done Callback to process asynchronous result
             *
             * @memberOf SignedData
             */
            SignedData.prototype.saveAsync = function (filename, format, done) {
                this.handle.saveAsync(filename, format, done);
            };
            ///**
            // * Create new signer
            // *
            // * @param {Certificate} cert Signer certificate
            // * @param {Key} key Private key for signer certificate
            // * @returns {Signer}
            // *
            // * @memberOf SignedData
            // */
            //public createSigner(cert: pki.Certificate, key: pki.Key): Signer {
            //    const signer: any = this.handle.createSigner(cert.handle, key.handle);
            //    return new Signer(signer);
            //}
            /**
             * Verify signature
             *
             * @param {Signer} [signer] Certificate
             * @returns {boolean}
             *
             * @memberOf SignedData
             */
            SignedData.prototype.verify = function (signer) {
                if (signer) {
                    return this.handle.verify(signer.handle);
                }
                else {
                    return this.handle.verify();
                }
            };
            /**
             * Verify signature asynchronously
             *
             * @param {Signer} [signer] Certificate
             * @param {(error: string, result: boolean) => void} done Callback to get returned value or error
             *
             * @memberOf SignedData
             */
            SignedData.prototype.verifyAsync = function (done, signer) {
                if (signer) {
                    this.handle.verifyAsync(done, signer.handle);
                }
                else {
                    this.handle.verifyAsync(done);
                }
            };
            Object.defineProperty(SignedData.prototype, "signParams", {
                /**
                 * Return signature creation parameters
                 *
                 * @type {TimestampParams | CadesParams}
                 * @memberOf SignedData
                 */
                get: function () {
                    var internalValue = this.handle.getSignParams();
                    var result = undefined;
                    if (internalValue instanceof native.CMS.TimestampParams) {
                        result = new TimestampParams();
                        result.handle = internalValue;
                    }
                    else if (internalValue instanceof native.CMS.CadesParams) {
                        result = new CadesParams();
                        result.handle = internalValue;
                    }
                    return result;
                },
                /**
                 * Set signature creation parameters
                 *
                 *
                 * @memberOf SignedData
                 */
                set: function (params) {
                    if (params == undefined)
                        throw new TypeError("SignedData::signParams: Wrong input param"); //return?
                    this.handle.setSignParams(params.handle);
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Create sign
             *
             * @param {Certificate} [certs] Certificate
             *
             * @memberOf SignedData
             */
            SignedData.prototype.sign = function (cert) {
                this.handle.sign(cert.handle);
            };
            /**
             * Create sign asynchronously
             *
             * @param {Certificate} [certs] Certificate
             * @param {(message: string)=>void} done Callback to process asynchronous result
             *
             * @memberOf SignedData
             */
            SignedData.prototype.signAsync = function (cert, done) {
                this.handle.signAsync(cert.handle, done);
            };
            return SignedData;
        }(trusted.BaseObject));
        cms_1.SignedData = SignedData;
    })(cms = trusted.cms || (trusted.cms = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * cryptographic service provider (CSP) helper
         * Uses on WIN32 or with CPROCSP
         *
         * @export
         * @class Csp
         * @extends {BaseObject<native.UTILS.Csp>}
         */
        var Csp = /** @class */ (function (_super) {
            __extends(Csp, _super);
            /**
             * Creates an instance of Csp.
             *
             *
             * @memberOf Csp
             */
            function Csp() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.Csp();
                return _this;
            }
            /**
             * Check available provaider for GOST 2001
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.isGost2001CSPAvailable = function () {
                var csp = new native.UTILS.Csp();
                return csp.isGost2001CSPAvailable();
            };
            /**
             * Check available provaider for GOST 2012-256
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.isGost2012_256CSPAvailable = function () {
                var csp = new native.UTILS.Csp();
                return csp.isGost2012_256CSPAvailable();
            };
            /**
             * Check available provaider for GOST 2012-512
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.isGost2012_512CSPAvailable = function () {
                var csp = new native.UTILS.Csp();
                return csp.isGost2012_512CSPAvailable();
            };
            /**
             * Verify license for CryptoPro CSP
             * Throw exception if provaider not available
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.checkCPCSPLicense = function () {
                var csp = new native.UTILS.Csp();
                return csp.checkCPCSPLicense();
            };
            /**
             * Return instaled correct license for CryptoPro CSP
             * Throw exception if provaider not available
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.getCPCSPLicense = function () {
                var csp = new native.UTILS.Csp();
                return csp.getCPCSPLicense();
            };
            /**
             * Return instaled correct version for CryptoPro CSP
             * Throw exception if provaider not available
             *
             * @static
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.getCPCSPVersion = function () {
                var csp = new native.UTILS.Csp();
                return csp.getCPCSPVersion();
            };
            Csp.getCPCSPVersionPKZI = function () {
                var csp = new native.UTILS.Csp();
                return csp.getCPCSPVersionPKZI();
            };
            Csp.getCPCSPVersionSKZI = function () {
                var csp = new native.UTILS.Csp();
                return csp.getCPCSPVersionSKZI();
            };
            Csp.getCPCSPSecurityLvl = function () {
                var csp = new native.UTILS.Csp();
                return csp.getCPCSPSecurityLvl();
            };
            /**
                    * Enumerate available CSP
                    *
                    * @static
                    * @returns {object[]} {type: nuber, name: string}
                    * @memberof Csp
                    */
            Csp.enumProviders = function () {
                var csp = new native.UTILS.Csp();
                return csp.enumProviders();
            };
            /**
             * Enumerate conainers
             *
             * @static
             * @param {number} [type]
             * @returns {string[]} Fully Qualified Container Name
             * @memberof Csp
             */
            Csp.enumContainers = function (type, provName) {
                if (provName === void 0) { provName = ""; }
                var csp = new native.UTILS.Csp();
                return csp.enumContainers(type, provName);
            };
            /**
             * Get certificate by container and provider props
             *
             * @static
             * @param {string} contName
             * @param {number} provType
             * @param {string} [provName=""]
             * @returns {pki.Certificate}
             * @memberof Csp
             */
            // tslint:disable-next-line:max-line-length
            Csp.getCertificateFromContainer = function (contName, provType, provName) {
                if (provName === void 0) { provName = ""; }
                var cert = new trusted.pki.Certificate();
                var csp = new native.UTILS.Csp();
                cert.handle = csp.getCertificateFromContainer(contName, provType, provName);
                return cert;
            };
            Csp.installCertificateFromContainer = function (contName, provType, provName) {
                if (provName === void 0) { provName = ""; }
                var csp = new native.UTILS.Csp();
                csp.installCertificateFromContainer(contName, provType, provName);
                return;
            };
            Csp.installCertificateToContainer = function (cert, contName, provType, provName) {
                if (provName === void 0) { provName = ""; }
                var csp = new native.UTILS.Csp();
                csp.installCertificateToContainer(cert.handle, contName, provType, provName);
                return;
            };
            Csp.deleteContainer = function (contName, provType, provName) {
                if (provName === void 0) { provName = ""; }
                var csp = new native.UTILS.Csp();
                csp.deleteContainer(contName, provType, provName);
                return;
            };
            /**
             * Get container name by certificate
             *
             * @static
             * @param {pki.Certificate} cert
             * @param {string} [category="MY"]
             * @returns {string}
             * @memberof Csp
             */
            Csp.getContainerNameByCertificate = function (cert, category) {
                if (category === void 0) { category = "MY"; }
                var csp = new native.UTILS.Csp();
                return csp.getContainerNameByCertificate(cert.handle, category);
            };
            /**
             * Ensure that the certificate's private key is available
             *
             * @static
             * @param {Certificate} cert
             * @returns {boolean}
             * @memberOf Csp
             */
            Csp.prototype.hasPrivateKey = function (cert) {
                return this.handle.hasPrivateKey(cert.handle);
            };
            Csp.buildChain = function (cert) {
                var csp = new native.UTILS.Csp();
                var certscol = new trusted.pki.CertificateCollection(csp.buildChain(cert.handle));
                return certscol;
            };
            Csp.buildChainAsync = function (cert, done) {
                var csp = new native.UTILS.Csp();
                csp.buildChainAsync(cert.handle, function (error, certs) {
                    if (error) {
                        done(error, null);
                        return;
                    }
                    var certscol = new trusted.pki.CertificateCollection(certs);
                    done(null, certscol);
                });
            };
            Csp.verifyCertificateChain = function (cert) {
                var csp = new native.UTILS.Csp();
                return csp.verifyCertificateChain(cert.handle);
            };
            Csp.verifyCertificateChainAsync = function (cert, done) {
                var csp = new native.UTILS.Csp();
                return csp.verifyCertificateChainAsync(cert.handle, done);
            };
            Csp.verifyCRL = function (crl) {
                var csp = new native.UTILS.Csp();
                return csp.verifyCRL(crl.handle);
            };
            /**
             * Find certificate in MY store and check that private key exportable
             *
             * @static
             * @param {pki.Certificate} cert
             * @returns {boolean}
             * @memberof Csp
             */
            Csp.isHaveExportablePrivateKey = function (cert) {
                var csp = new native.UTILS.Csp();
                return csp.isHaveExportablePrivateKey(cert.handle);
            };
            /**
             * Create Pkcs by cert
             * NOTE:  only for certificates with exportable key. Check it by isHaveExportablePrivateKey
             *
             * @static
             * @param {pki.Certificate} cert
             * @param {boolean} exportPrivateKey
             * @param {string} [password]
             * @returns {pki.PKCS12}
             * @memberof Csp
             */
            Csp.certToPkcs12 = function (cert, exportPrivateKey, password) {
                var csp = new native.UTILS.Csp();
                return trusted.pki.PKCS12.wrap(csp.certToPkcs12(cert.handle, exportPrivateKey, password));
            };
            /**
             * Import PFX to store
             *
             * @static
             * @param {pki.PKCS12} p12
             * @param {string} [password]
             * @returns {void}
             * @memberof Csp
             */
            Csp.importPkcs12 = function (p12, password) {
                var csp = new native.UTILS.Csp();
                csp.importPkcs12(p12.handle, password);
                return;
            };
            return Csp;
        }(trusted.BaseObject));
        utils.Csp = Csp;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * ModuleInfo class
         *
         * @export
         * @class ModuleInfo
         * @extends {BaseObject<native.UTILS.ModuleInfo>}
         */
        var ModuleInfo = /** @class */ (function (_super) {
            __extends(ModuleInfo, _super);
            /**
             * Creates an instance of ModuleInfo.
             *
             *
             * @memberOf ModuleInfo
             */
            function ModuleInfo() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.ModuleInfo();
                return _this;
            }
            Object.defineProperty(ModuleInfo.prototype, "version", {
                /**
                 * Return module version
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf ModuleInfo
                 */
                get: function () {
                    return this.handle.getModuleVersion();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ModuleInfo.prototype, "name", {
                /**
                 * Return module name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf ModuleInfo
                 */
                get: function () {
                    return this.handle.getModuleName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ModuleInfo.prototype, "cadesEnabled", {
                /**
                 * CAdES support flag
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberOf ModuleInfo
                 */
                get: function () {
                    return this.handle.getCadesEnabled();
                },
                enumerable: true,
                configurable: true
            });
            return ModuleInfo;
        }(trusted.BaseObject));
        utils.ModuleInfo = ModuleInfo;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * Tools class
         *
         * @export
         * @class Tools
         * @extends {BaseObject<native.UTILS.Tools>}
         */
        var Tools = /** @class */ (function (_super) {
            __extends(Tools, _super);
            function Tools() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.Tools();
                return _this;
            }
            Tools.prototype.stringFromBase64 = function (instr, flag) {
                return this.handle.stringFromBase64(instr, flag);
            };
            Tools.prototype.stringToBase64 = function (instr, flag) {
                return this.handle.stringToBase64(instr, flag);
            };
            return Tools;
        }(trusted.BaseObject));
        utils.Tools = Tools;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * JSON Web Token (JWT)
         * Uses only with CTGOSTCP
         *
         * @export
         * @class Jwt
         * @extends {BaseObject<native.JWT.Jwt>}
         */
        var Jwt = /** @class */ (function (_super) {
            __extends(Jwt, _super);
            /**
             * Creates an instance of Jwt.
             *
             *
             * @memberOf Jwt
             */
            function Jwt() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.Jwt();
                return _this;
            }
            /**
             * Create Header JWT
             * Return 0 if license correct
             *
             * @returns {number}
             *
             * @memberOf Jwt
             */
            Jwt.prototype.createHeader = function (alg) {
                return (this.handle.createHeader(alg));
            };
            /**
             * Create Payload JWT
             * Return 0 if license correct
             *
             * @returns {number}
             *
             * @memberOf Jwt
             */
            Jwt.prototype.createPayload = function (aud, sub, core, nbf, iss, exp, iat, jti, desc) {
                return this.handle.createPayload(aud, sub, core, nbf, iss, exp, iat, jti, desc);
            };
            /**
             * Create JWT Token
             *
             * @returns {number}
             *
             * @memberOf Jwt
             */
            Jwt.prototype.createJWTToken = function (header, payload, privateKey) {
                return this.handle.createJWTToken(header, payload, privateKey);
            };
            /**
             * Verify JWT Token
             *
             * @returns {number}
             *
             * @memberOf Jwt
             */
            Jwt.prototype.verifyJWTToken = function (jwtToken, publicKey) {
                return this.handle.verifyJWTToken(jwtToken, publicKey);
            };
            return Jwt;
        }(trusted.BaseObject));
        utils.Jwt = Jwt;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * JSON Web Token (DLV)
         * Uses only with CTGOSTCP
         *
         * @export
         * @class Dlv
         * @extends {BaseObject<native.DLV.DLV>}
         */
        var Dlv = /** @class */ (function (_super) {
            __extends(Dlv, _super);
            /**
             * Add dlv license to store
             * License must be correct
             *
             * @static
             * @param {string} license license token in DLV format
             * @returns {boolean}
             * @memberof Dlv
             */
            function Dlv() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.Dlv();
                return _this;
            }
            /**
             * Verify dlv license file
             * Return 0 if license correct
             *
             * @returns {number}
             *
             * @memberOf Dlv
             */
            Dlv.prototype.licenseValidateFormat = function (lic) {
                return this.handle.licenseValidateFormat(lic);
            };
            /**
             * Verify dlv license file
             * Return 0 if license correct
             *
             * @returns {number}
             *
             * @memberOf Dlv
             */
            Dlv.prototype.checkLicense = function (lic) {
                return this.handle.checkLicense(lic);
            };
            return Dlv;
        }(trusted.BaseObject));
        utils.Dlv = Dlv;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * Object for calculating data hash
         *
         * @export
         * @class Hash
         * @extends {BaseObject<native.UTILS.Hash>}
         */
        var Hash = /** @class */ (function (_super) {
            __extends(Hash, _super);
            /**
             * Creates an instance of Hash.
             *
             * @param {trusted.HashAlg} hash_alg Hash algorithm ID
             *
             * @memberOf Hash
             */
            function Hash(hash_alg) {
                var _this = _super.call(this) || this;
                if (undefined === hash_alg || null === hash_alg) {
                    throw new TypeError("Hash::constructor: Wrong input param");
                }
                _this.handle = new native.UTILS.Hash(hash_alg);
                return _this;
            }
            /**
             * Add data to hash
             *
             * @param {Buffer} buffer Buffer with data to add into hash
             * @memberof Hash
             */
            Hash.prototype.addData = function (buffer) {
                this.handle.addData(buffer);
            };
            /**
             * Get value of hashed data
             *
             * @returns {Buffer} Buffer with hash value
             * @memberof Hash
             */
            Hash.prototype.getValue = function () {
                return this.handle.getValue();
            };
            /**
             * Hash data from buffer
             *
             * @static
             * @param {trusted.HashAlg} hash_alg Hash algorithm ID
             * @param {Buffer} data Buffer with data to hash
             * @returns {Buffer}
             * @memberof Hash
             */
            Hash.hashData = function (hash_alg, data) {
                var hash = new native.UTILS.Hash();
                return hash.hashData(hash_alg, data);
            };
            /**
             * Hash data from buffer asynchronously
             *
             * @static
             * @param {trusted.HashAlg} hash_alg Hash algorithm ID
             * @param {Buffer} data Buffer with data to hash
             * @returns {Buffer}
             * @memberof Hash
             */
            Hash.hashDataAsync = function (hash_alg, data, done) {
                var hash = new native.UTILS.Hash();
                return hash.hashDataAsync(hash_alg, data, done);
            };
            return Hash;
        }(trusted.BaseObject));
        utils.Hash = Hash;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * JSON Web Token (LICENSE_MNG)
         * Uses only with CTGOSTCP
         *
         * @export
         * @class License_Mng
         * @extends {BaseObject<native.LICENSE_MNG.License_Mng>}
         */
        var License_Mng = /** @class */ (function (_super) {
            __extends(License_Mng, _super);
            /**
              * Creates an instance of License_Mng.
              *
              *
              * @memberOf License_Mng
              */
            function License_Mng() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.License_Mng();
                return _this;
            }
            /**
              * Add license_mng license to store
              * License must be correct
              *
              * @static
              * @param {string} license license token in LICENSE_MNG format
              * @returns {boolean}
              * @memberof License_Mng
              */
            License_Mng.prototype.addLicense = function (lic) {
                return this.handle.addLicense(lic);
            };
            /**
              * Add license_mng license to store
              * License must be correct
              *
              * @static
              * @param {string} license license token in LICENSE_MNG format
              * @returns {boolean}
              * @memberof License_Mng
              */
            License_Mng.prototype.addLicenseFromFile = function (lic) {
                return this.handle.addLicenseFromFile(lic);
            };
            /**
             * Delete license_mng license from store
             *
             * @static
             * @param {string} license license token
             * @returns {boolean}
             * @memberof License_Mng
             */
            License_Mng.prototype.deleteLicense = function (lic) {
                return this.handle.deleteLicense(lic);
            };
            /**
             * Delete license_mng license from store
             *
             * @static
             * @param {string} license license token
             * @returns {boolean}
             * @memberof License_Mng
             */
            License_Mng.prototype.deleteLicenseOfIndex = function (index) {
                return this.handle.deleteLicenseOfIndex(index);
            };
            /**
             * Delete license_mng license from store
             *
             * @static
             * @param {string} license license token
             * @returns {boolean}
             * @memberof License_Mng
             */
            License_Mng.prototype.getCountLicense = function () {
                return this.handle.getCountLicense();
            };
            /**
            * Delete license_mng license from store
            *
            * @static
            * @param {string} license license token
            * @returns {boolean}
            * @memberof License_Mng
            */
            License_Mng.prototype.getLicense = function (index) {
                return this.handle.getLicense(index);
            };
            /**
             * Delete license_mng license from store
             *
             * @static
             * @param {string} license license token
             * @returns {boolean}
             * @memberof License_Mng
             */
            License_Mng.prototype.checkLicense = function (lic) {
                return this.handle.checkLicense(lic);
            };
            License_Mng.prototype.checkLicenseOfIndex = function (index) {
                return this.handle.checkLicenseOfIndex(index);
            };
            License_Mng.prototype.accessOperations = function () {
                return this.handle.accessOperations();
            };
            License_Mng.prototype.generateTrial = function () {
                return this.handle.generateTrial();
            };
            License_Mng.prototype.checkTrialLicense = function () {
                return this.handle.checkTrialLicense();
            };
            return License_Mng;
        }(trusted.BaseObject));
        utils.License_Mng = License_Mng;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var utils;
    (function (utils) {
        /**
         * Connection settings for TSP and OCSP
         *
         * @export
         * @class ConnectionSettings
         * @extends {BaseObject<native.UTILS.ConnectionSettings>}
         */
        var ConnectionSettings = /** @class */ (function (_super) {
            __extends(ConnectionSettings, _super);
            /**
             * Creates an instance of ConnectionSettings.
             *
             *
             * @memberOf ConnectionSettings
             */
            function ConnectionSettings() {
                var _this = _super.call(this) || this;
                _this.handle = new native.UTILS.ConnectionSettings();
                return _this;
            }
            Object.defineProperty(ConnectionSettings.prototype, "AuthType", {
                /**
                 * Service authentication type getter
                 *
                 *
                 * @type {number}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.AuthType;
                },
                /**
                 * Service authentication type setter
                 *
                 *
                 * @type {number}
                 * @memberof ConnectionSettings
                 */
                set: function (authType) {
                    this.handle.AuthType = authType;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "Address", {
                /**
                 * Service address getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.Address;
                },
                /**
                 * Service address setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (addr) {
                    this.handle.Address = addr;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "UserName", {
                /**
                 * Service user name getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.UserName;
                },
                /**
                 * Service user name setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (usrName) {
                    this.handle.UserName = usrName;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "Password", {
                /**
                 * Service password getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.Password;
                },
                /**
                 * Service password setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (passwd) {
                    this.handle.Password = passwd;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "ClientCertificate", {
                /**
                 * Client certificate getter
                 *
                 *
                 * @type {pki.Certificate}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    var cert = this.handle.ClientCertificate;
                    if (cert) {
                        return trusted.pki.Certificate.wrap(cert);
                    }
                    else {
                        return undefined;
                    }
                },
                /**
                 * Client certificate setter
                 *
                 *
                 * @type {pki.Certificate}
                 * @memberof ConnectionSettings
                 */
                set: function (clntCert) {
                    if (clntCert !== undefined) {
                        this.handle.ClientCertificate = clntCert.handle;
                    }
                    else {
                        this.handle.ClientCertificate = undefined;
                    }
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "ProxyAuthType", {
                /**
                 * Proxy authentication type getter
                 *
                 *
                 * @type {number}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.ProxyAuthType;
                },
                /**
                 * Proxy authentication type setter
                 *
                 *
                 * @type {number}
                 * @memberof ConnectionSettings
                 */
                set: function (authType) {
                    this.handle.ProxyAuthType = authType;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "ProxyAddress", {
                /**
                 * Proxy address getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.ProxyAddress;
                },
                /**
                 * Proxy address setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (addr) {
                    this.handle.ProxyAddress = addr;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "ProxyUserName", {
                /**
                 * Proxy user name getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.ProxyUserName;
                },
                /**
                 * Proxy user name setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (usrName) {
                    this.handle.ProxyUserName = usrName;
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ConnectionSettings.prototype, "ProxyPassword", {
                /**
                 * Proxy password getter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                get: function () {
                    return this.handle.ProxyPassword;
                },
                /**
                 * Proxy password setter
                 *
                 *
                 * @type {string}
                 * @memberof ConnectionSettings
                 */
                set: function (passwd) {
                    this.handle.ProxyPassword = passwd;
                },
                enumerable: true,
                configurable: true
            });
            return ConnectionSettings;
        }(trusted.BaseObject));
        utils.ConnectionSettings = ConnectionSettings;
    })(utils = trusted.utils || (trusted.utils = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Wrap ASN1_OBJECT
         *
         * @export
         * @class Oid
         * @extends {BaseObject<native.PKI.OID>}
         */
        var Oid = /** @class */ (function (_super) {
            __extends(Oid, _super);
            /**
             * Creates an instance of Oid.
             * @param {(native.PKI.OID | string)} param
             *
             * @memberOf Oid
             */
            function Oid(param) {
                var _this = _super.call(this) || this;
                if (typeof (param) === "string") {
                    _this.handle = new native.PKI.OID(param);
                }
                else if (param instanceof native.PKI.OID) {
                    _this.handle = param;
                }
                else {
                    throw new TypeError("Oid::constructor: Wrong input param");
                }
                return _this;
            }
            Object.defineProperty(Oid.prototype, "value", {
                /**
                 * Return text value for OID
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Oid
                 */
                get: function () {
                    return this.handle.getValue();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Oid.prototype, "longName", {
                /**
                 * Return OID long name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Oid
                 */
                get: function () {
                    return this.handle.getLongName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Oid.prototype, "shortName", {
                /**
                 * Return OID short name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Oid
                 */
                get: function () {
                    return this.handle.getShortName();
                },
                enumerable: true,
                configurable: true
            });
            return Oid;
        }(trusted.BaseObject));
        pki.Oid = Oid;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Wrap X509_EXTENSION
         *
         * @export
         * @class Extension
         * @extends {BaseObject<native.PKI.Extension>}
         */
        var Extension = /** @class */ (function (_super) {
            __extends(Extension, _super);
            /**
             * Creates an instance of Extension.
             * @param {native.PKI.OID} [oid]
             * @param {string} [value]
             * @memberof Extension
             */
            function Extension(oid, value) {
                var _this = _super.call(this) || this;
                if (oid && oid instanceof pki.Oid && value) {
                    _this.handle = new native.PKI.Extension(oid.handle, value);
                }
                else if (arguments[0] instanceof native.PKI.Extension) {
                    _this.handle = arguments[0];
                }
                else {
                    _this.handle = new native.PKI.Extension();
                }
                return _this;
            }
            Object.defineProperty(Extension.prototype, "typeId", {
                /**
                 * Return extension oid
                 *
                 * @readonly
                 * @type {Oid}
                 * @memberof Extension
                 */
                get: function () {
                    return new pki.Oid(this.handle.getTypeId());
                },
                /**
                 * Set extension oid
                 *
                 * @memberof Extension
                 */
                set: function (oid) {
                    this.handle.setTypeId(oid.handle);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Extension.prototype, "critical", {
                /**
                 * Get critical
                 *
                 * @type {boolean}
                 * @memberof Extension
                 */
                get: function () {
                    return this.handle.getCritical();
                },
                /**
                 * Set critical
                 *
                 * @memberof Extension
                 */
                set: function (critical) {
                    this.handle.setCritical(critical);
                },
                enumerable: true,
                configurable: true
            });
            return Extension;
        }(trusted.BaseObject));
        pki.Extension = Extension;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Collection of Extension
         *
         * @export
         * @class ExtensionCollection
         * @extends {BaseObject<native.PKI.ExtensionCollection>}
         * @implements {core.ICollectionWrite}
         */
        var ExtensionCollection = /** @class */ (function (_super) {
            __extends(ExtensionCollection, _super);
            /**
             * Creates an instance of ExtensionCollection.
             * @param {native.PKI.ExtensionCollection} [param]
             * @memberof ExtensionCollection
             */
            function ExtensionCollection(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.ExtensionCollection) {
                    _this.handle = param;
                }
                else {
                    _this.handle = new native.PKI.ExtensionCollection();
                }
                return _this;
            }
            /**
             * Return element by index from collection
             *
             * @param {number} index
             * @returns {Extension}
             * @memberof ExtensionCollection
             */
            ExtensionCollection.prototype.items = function (index) {
                return pki.Extension.wrap(this.handle.items(index));
            };
            Object.defineProperty(ExtensionCollection.prototype, "length", {
                /**
                 * Return collection length
                 *
                 * @readonly
                 * @type {number}
                 * @memberof ExtensionCollection
                 */
                get: function () {
                    return this.handle.length();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Add new element to collection
             *
             * @param {Extension} ext
             * @memberof ExtensionCollection
             */
            ExtensionCollection.prototype.push = function (ext) {
                this.handle.push(ext.handle);
            };
            /**
             * Remove last element from collection
             *
             * @memberof ExtensionCollection
             */
            ExtensionCollection.prototype.pop = function () {
                this.handle.pop();
            };
            /**
             * Remove element by index from collection
             *
             * @param {number} index
             * @memberof ExtensionCollection
             */
            ExtensionCollection.prototype.removeAt = function (index) {
                this.handle.removeAt(index);
            };
            return ExtensionCollection;
        }(trusted.BaseObject));
        pki.ExtensionCollection = ExtensionCollection;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.DER;
        /**
         * Wrap X509
         *
         * @export
         * @class Certificate
         * @extends {BaseObject<native.PKI.Certificate>}
         */
        var Certificate = /** @class */ (function (_super) {
            __extends(Certificate, _super);
            /**
             * Creates an instance of Certificate.
             * @param {native.PKI.Certificate | native.PKI.CertificationRequest} [param]
             *
             * @memberOf Certificate
             */
            function Certificate(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.Certificate) {
                    _this.handle = param;
                }
                else if (param instanceof pki.CertificationRequest) {
                    _this.handle = new native.PKI.Certificate(param.handle);
                }
                else {
                    _this.handle = new native.PKI.Certificate();
                }
                return _this;
            }
            /**
             * Load certificate from file
             *
             * @static
             * @param {string} filename File location
             * @param {DataFormat} [format] PEM | DER
             * @returns {Certificate}
             *
             * @memberOf Certificate
             */
            Certificate.load = function (filename, format) {
                var cert = new Certificate();
                cert.handle.load(filename, format);
                return cert;
            };
            /**
             * Load certificate from memory
             *
             * @static
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             * @returns {Certificate}
             *
             * @memberOf Certificate
             */
            Certificate.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                var cert = new Certificate();
                cert.handle.import(buffer, format);
                return cert;
            };
            Object.defineProperty(Certificate.prototype, "version", {
                /**
                 * Return version of certificate
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getVersion();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "serialNumber", {
                /**
                 * Return serial number of certificate
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getSerialNumber().toString();
                },
                /**
                 * Return serial number of certificate
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                set: function (serial) {
                    this.handle.setSerialNumber(serial);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "keyUsage", {
                /**
                 * Return KeyUsageFlags bit mask
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getKeyUsage();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "keyUsageString", {
                /**
                 * Return Key Usage Flags array
                 *
                 * @readonly
                 * @type {string[]}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getKeyUsageString();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "enhancedKeyUsage", {
                /**
                 * Return enhanced Key Usage values array
                 *
                 * @readonly
                 * @type {string[]}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getEnhancedKeyUsage();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "issuerFriendlyName", {
                /**
                 * Return CN from issuer name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getIssuerFriendlyName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "issuerName", {
                /**
                 * Return issuer name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getIssuerName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "subjectFriendlyName", {
                /**
                 * Return CN from subject name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getSubjectFriendlyName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "subjectName", {
                /**
                 * Return subject name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getSubjectName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "notBefore", {
                /**
                 * Return Not Before date
                 *
                 * @readonly
                 * @type {Date}
                 * @memberOf Certificate
                 */
                get: function () {
                    return new Date(this.handle.getNotBefore());
                },
                /**
                 * Set not before. Use offset in sec
                 *
                 * @memberof Certificate
                 */
                set: function (offsetSec) {
                    if (typeof offsetSec === "number") {
                        this.handle.setNotBefore(offsetSec);
                    }
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "notAfter", {
                /**
                 * Return Not After date
                 *
                 * @readonly
                 * @type {Date}
                 * @memberOf Certificate
                 */
                get: function () {
                    return new Date(this.handle.getNotAfter());
                },
                /**
                 * Set not after. Use offset in sec
                 *
                 * @memberof Certificate
                 */
                set: function (offsetSec) {
                    if (typeof offsetSec === "number") {
                        this.handle.setNotAfter(offsetSec);
                    }
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "thumbprint", {
                /**
                 * Return SHA-1 thumbprint
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getThumbprint().toString("hex");
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "signatureAlgorithm", {
                /**
                 * Return signature algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getSignatureAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "signatureDigestAlgorithm", {
                /**
                 * Return signature digest algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getSignatureDigestAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "publicKeyAlgorithm", {
                /**
                 * Return public key algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getPublicKeyAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "organizationName", {
                /**
                 * Return organization name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getOrganizationName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "OCSPUrls", {
                /**
                 * Return array of OCSP urls
                 *
                 * @readonly
                 * @type {string[]}
                 * @memberof Certificate
                 */
                get: function () {
                    return this.handle.getOCSPUrls();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "CAIssuersUrls", {
                /**
                 * Return array of CA issuers urls
                 *
                 * @readonly
                 * @type {string[]}
                 * @memberof Certificate
                 */
                get: function () {
                    return this.handle.getCAIssuersUrls();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "subjectKeyIdentifier", {
                get: function () {
                    return this.handle.getSubjectKeyIdentifier().toString("hex");
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "isSelfSigned", {
                /**
                 * Return true is a certificate is self signed
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberof Certificate
                 */
                get: function () {
                    return this.handle.isSelfSigned();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Certificate.prototype, "isCA", {
                /**
                 * Return true if it CA certificate (can be used to sign other certificates)
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.isCA();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Signs certificate using the given private key
             *
             * @memberof Certificate
             */
            Certificate.prototype.sign = function () {
                this.handle.sign();
            };
            /**
             * Compare certificates
             *
             * @param {Certificate} cert Certificate for compare
             * @returns {number}
             *
             * @memberOf Certificate
             */
            Certificate.prototype.compare = function (cert) {
                var cmp = this.handle.compare(cert.handle);
                if (cmp < 0) {
                    return -1;
                }
                if (cmp > 0) {
                    return 1;
                }
                return 0;
            };
            /**
             * Compare certificates
             *
             * @param {Certificate} cert Certificate for compare
             * @returns {boolean}
             *
             * @memberOf Certificate
             */
            Certificate.prototype.equals = function (cert) {
                return this.handle.equals(cert.handle);
            };
            /**
             * Return certificate hash
             *
             * @param {string} [algorithm="sha1"]
             * @returns {String}
             *
             * @memberOf Certificate
             */
            Certificate.prototype.hash = function (algorithm) {
                if (algorithm === void 0) { algorithm = "sha1"; }
                return this.handle.hash(algorithm).toString("hex");
            };
            /**
             * Return certificate duplicat
             *
             * @returns {Certificate}
             *
             * @memberOf Certificate
             */
            Certificate.prototype.duplicate = function () {
                var cert = new Certificate();
                cert.handle = this.handle.duplicate();
                return cert;
            };
            /**
             * Load certificate from file location
             *
             * @param {string} filename File location
             * @param {DataFormat} [format]
             *
             * @memberOf Certificate
             */
            Certificate.prototype.load = function (filename, format) {
                this.handle.load(filename, format);
            };
            /**
             * Load certificate from memory
             *
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
             *
             * @memberOf Certificate
             */
            Certificate.prototype.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.import(buffer, format);
            };
            /**
             * Save certificate to memory
             *
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
             * @returns {Buffer}
             *
             * @memberOf Certificate
             */
            Certificate.prototype.export = function (format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                return this.handle.export(format);
            };
            /**
             * Write certificate to file
             *
             * @param {string} filename File location
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             *
             * @memberOf Certificate
             */
            Certificate.prototype.save = function (filename, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.save(filename, format);
            };
            /**
             * Display certificate properties in native Windows dialog. Windows only.
             *
             * @memberOf Certificate
             */
            Certificate.prototype.view = function () {
                this.handle.view();
            };
            return Certificate;
        }(trusted.BaseObject));
        pki.Certificate = Certificate;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Collection of Certificate
         *
         * @export
         * @class CertificateCollection
         * @extends {BaseObject<native.PKI.CertificateCollection>}
         * @implements {core.ICollectionWrite}
         */
        var CertificateCollection = /** @class */ (function (_super) {
            __extends(CertificateCollection, _super);
            /**
             * Creates an instance of CertificateCollection.
             * @param {native.PKI.CertificateCollection} [param]
             *
             * @memberOf CertificateCollection
             */
            function CertificateCollection(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.CertificateCollection) {
                    _this.handle = param;
                }
                else {
                    _this.handle = new native.PKI.CertificateCollection();
                }
                return _this;
            }
            /**
             * Return element by index from collection
             *
             * @param {number} index
             * @returns {Certificate}
             *
             * @memberOf CertificateCollection
             */
            CertificateCollection.prototype.items = function (index) {
                return pki.Certificate.wrap(this.handle.items(index));
            };
            Object.defineProperty(CertificateCollection.prototype, "length", {
                /**
                 * Return collection length
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf CertificateCollection
                 */
                get: function () {
                    return this.handle.length();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Add new element to collection
             *
             * @param {Certificate} cert
             *
             * @memberOf CertificateCollection
             */
            CertificateCollection.prototype.push = function (cert) {
                this.handle.push(cert.handle);
            };
            /**
             * Remove last element from collection
             *
             *
             * @memberOf CertificateCollection
             */
            CertificateCollection.prototype.pop = function () {
                this.handle.pop();
            };
            /**
             * Remove element by index from collection
             *
             * @param {number} index
             *
             * @memberOf CertificateCollection
             */
            CertificateCollection.prototype.removeAt = function (index) {
                this.handle.removeAt(index);
            };
            return CertificateCollection;
        }(trusted.BaseObject));
        pki.CertificateCollection = CertificateCollection;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.PEM;
        /**
         * Wrap X509_REQ
         *
         * @export
         * @class CertificationRequest
         * @extends {BaseObject<native.PKI.CertificationRequest>}
         */
        var CertificationRequest = /** @class */ (function (_super) {
            __extends(CertificationRequest, _super);
            // /**
            //  * Load request from file
            //  *
            //  * @static
            //  * @param {string} filename File location
            //  * @param {DataFormat} [format] PEM | DER
            //  *
            //  * @memberOf CertificationRequest
            //  */
            // public static load(filename: string, format?: DataFormat): CertificationRequest {
            //     const req: CertificationRequest = new CertificationRequest();
            //     req.handle.load(filename, format);
            //     return req;
            // }
            /**
             * Creates an instance of CertificationRequest.
             * @param {native.PKI.CertificationRequest} [param]
             *
             * @memberOf CertificationRequest
             */
            function CertificationRequest() {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKI.CertificationRequest();
                return _this;
            }
            // /**
            //  * Load request from file
            //  *
            //  * @param {string} filename File location
            //  * @param {DataFormat} [format] PEM | DER
            //  *
            //  * @memberOf CertificationRequest
            //  */
            // public load(filename: string, format?: DataFormat): void {
            //     this.handle.load(filename, format);
            // }
            /**
             * Write request to file
             *
             * @param {string} filename File path
             * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
             *
             * @memberOf CertificationRequest
             */
            CertificationRequest.prototype.save = function (filename, dataFormat) {
                if (dataFormat === void 0) { dataFormat = DEFAULT_DATA_FORMAT; }
                this.handle.save(filename, dataFormat);
            };
            Object.defineProperty(CertificationRequest.prototype, "subject", {
                // /**
                //  * Rerutn subject name
                //  *
                //  * @readonly
                //  * @type {string}
                //  * @memberof CertificationRequest
                //  */
                // get subject(): string | native.PKI.INameField[] {
                //     return this.handle.getSubject();
                // }
                /**
                 * Sets the subject of this certification request.
                 *
                 * @param {string | native.PKI.INameField[]} x509name Example "/C=US/O=Test/CN=example.com"
                 *
                 * @memberOf CertificationRequest
                 */
                set: function (x509name) {
                    var normalizedName = "";
                    if (x509name instanceof Array) {
                        for (var _i = 0, x509name_1 = x509name; _i < x509name_1.length; _i++) {
                            var field = x509name_1[_i];
                            if (field.type && field.value) {
                                normalizedName += ",";
                                normalizedName += field.type;
                                normalizedName += "=";
                                normalizedName += "\"" + (field.value).replace(/"/g, '""') + "\"";
                            }
                        }
                    }
                    else {
                        normalizedName = x509name;
                    }
                    this.handle.setSubject(normalizedName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "version", {
                // /**
                //  * Rerutn subject public key
                //  *
                //  * @readonly
                //  * @type {Key}
                //  * @memberof CertificationRequest
                //  */
                // get publicKey(): Key {
                //     return Key.wrap<native.PKI.Key, Key>(this.handle.getPublicKey());
                // }
                // /**
                //  *  Set public key
                //  *
                //  *  @param {Key} pubkey Public key
                //  *
                //  * @memberOf CertificationRequest
                //  */
                // set publicKey(pubkey: pki.Key) {
                //     this.handle.setPublicKey(pubkey.handle);
                // }
                /**
                 * Rerutn version
                 *
                 * @readonly
                 * @type {number}
                 * @memberof CertificationRequest
                 */
                get: function () {
                    return this.handle.getVersion();
                },
                /**
                 * Set version certificate
                 *
                 * @param {number} version
                 *
                 * @memberOf CertificationRequest
                 */
                set: function (version) {
                    this.handle.setVersion(version);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "extensions", {
                // /**
                //  * Rerutn extensions
                //  *
                //  * @readonly
                //  * @type {ExtensionCollection}
                //  * @memberof CertificationRequest
                //  */
                // get extensions(): pki.ExtensionCollection {
                //     return ExtensionCollection.wrap<native.PKI.ExtensionCollection, ExtensionCollection>(
                //         this.handle.getExtensions());
                // }
                /**
                 * Set extensions
                 *
                 * @param {ExtensionCollection} exts
                 *
                 * @memberOf CertificationRequest
                 */
                set: function (exts) {
                    this.handle.setExtensions(exts.handle);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "containerName", {
                /**
                 * Rerutn containerName
                 *
                 * @readonly
                 * @type {string}
                 * @memberof CertificationRequest
                 */
                get: function () {
                    return this.handle.getContainerName();
                },
                /**
                 * Set containerName
                 *
                 * @readonly
                 * @type {string}
                 * @memberof CertificationRequest
                 */
                set: function (x509name) {
                    this.handle.setContainerName(x509name);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "pubKeyAlgorithm", {
                /**
                 * Rerutn PubKeyAlgorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberof CertificationRequest
                 */
                get: function () {
                    return this.handle.getPubKeyAlgorithm();
                },
                /**
                 * Set PubKeyAlgorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberof CertificationRequest
                 */
                set: function (x509name) {
                    this.handle.setPubKeyAlgorithm(x509name);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "exportableFlag", {
                /**
                 * Rerutn exportableFlag
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberof CertificationRequest
                 */
                get: function () {
                    return this.handle.getExportableFlag();
                },
                /**
                 * Set exportableFlag
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberof CertificationRequest
                 */
                set: function (flag) {
                    this.handle.setExportableFlag(flag);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CertificationRequest.prototype, "newKeysetFlag", {
                /**
                 * Rerutn newKeysetFlag
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberof CertificationRequest
                 */
                get: function () {
                    return this.handle.getNewKeysetFlag();
                },
                /**
                 * Set newKeysetFlag
                 *
                 * @readonly
                 * @type {boolean}
                 * @memberof CertificationRequest
                 */
                set: function (flag) {
                    this.handle.setNewKeysetFlag(flag);
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Create X509 certificate from request
             *
             * @param {number} days
             * @param {Key} key
             * @returns {Certificate}
             * @memberof CertificationRequest
             */
            CertificationRequest.prototype.toCertificate = function (notAfter, serial) {
                if (notAfter === void 0) { notAfter = 31536000; }
                if (serial === void 0) { serial = ""; }
                return pki.Certificate.wrap(this.handle.toCertificate(notAfter, serial));
            };
            return CertificationRequest;
        }(trusted.BaseObject));
        pki.CertificationRequest = CertificationRequest;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.DER;
        /**
         * Wrap CRL
         *
         * @export
         * @class CRL
         * @extends {BaseObject<native.PKI.CRL>}
         */
        var CRL = /** @class */ (function (_super) {
            __extends(CRL, _super);
            /**
             * Creates an instance of CRL.
             * @param {native.PKI.CRL} [param]
             *
             * @memberOf Certificate
             */
            function CRL(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.CRL) {
                    _this.handle = param;
                }
                else {
                    _this.handle = new native.PKI.CRL();
                }
                return _this;
            }
            /**
             * Load CRL from file
             *
             * @static
             * @param {string} filename File location
             * @param {DataFormat} [format] PEM | DER
             * @returns {CRL}
             *
             * @memberOf CRL
             */
            CRL.load = function (filename, format) {
                var crl = new CRL();
                crl.handle.load(filename, format);
                return crl;
            };
            /**
             * Load CRL from memory
             *
             * @static
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             * @returns {CRL}
             *
             * @memberOf CRL
             */
            CRL.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                var crl = new CRL();
                crl.handle.import(buffer, format);
                return crl;
            };
            Object.defineProperty(CRL.prototype, "version", {
                /**
                 * Return version of CRL
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf Certificate
                 */
                get: function () {
                    return this.handle.getVersion();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "issuerName", {
                /**
                * Return issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf CRL
                */
                get: function () {
                    return this.handle.getIssuerName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "issuerFriendlyName", {
                /**
                 * Return CN from issuer name
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getIssuerFriendlyName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "lastUpdate", {
                /**
                 * Return last update date
                 *
                 * @readonly
                 * @type {Date}
                 * @memberOf CRL
                 */
                get: function () {
                    return new Date(this.handle.getLastUpdate());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "nextUpdate", {
                /**
                 * Return next update date
                 *
                 * @readonly
                 * @type {Date}
                 * @memberOf CRL
                 */
                get: function () {
                    return new Date(this.handle.getNextUpdate());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "thumbprint", {
                /**
                 * Return SHA-1 thumbprint
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getThumbprint().toString("hex");
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "signatureAlgorithm", {
                /**
                 * Return signature algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getSignatureAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "signatureDigestAlgorithm", {
                /**
                 * Return signature digest algorithm
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getSignatureDigestAlgorithm();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "authorityKeyid", {
                /**
                 * Return authority keyid
                 *
                 * @readonly
                 * @type {string}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getAuthorityKeyid().toString("hex");
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(CRL.prototype, "crlNumber", {
                /**
                 * Return CRL number
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf CRL
                 */
                get: function () {
                    return this.handle.getCrlNumber();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Load CRL from file
             *
             * @param {string} filename File location
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
             *
             * @memberOf CRL
             */
            CRL.prototype.load = function (filename, format) {
                this.handle.load(filename, format);
            };
            /**
             * Load CRL from memory
             *
             * @param {Buffer} buffer
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
             *
             * @memberOf CRL
             */
            CRL.prototype.import = function (buffer, format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.import(buffer, format);
            };
            /**
             * Save CRL to memory
             *
             * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
             * @returns {Buffer}
             *
             * @memberOf CRL
             */
            CRL.prototype.export = function (format) {
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                return this.handle.export(format);
            };
            /**
             * Write CRL to file
             *
             * @param {string} filename File location
             * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
             *
             * @memberOf CRL
             */
            CRL.prototype.save = function (filename, dataFormat) {
                if (dataFormat === void 0) { dataFormat = DEFAULT_DATA_FORMAT; }
                this.handle.save(filename, dataFormat);
            };
            /**
             * Compare CRLs
             *
             * @param {CRL} crl CRL for compare
             * @returns {number}
             *
             * @memberOf CRL
             */
            CRL.prototype.compare = function (crl) {
                var cmp = this.handle.compare(crl.handle);
                if (cmp < 0) {
                    return -1;
                }
                if (cmp > 0) {
                    return 1;
                }
                return 0;
            };
            /**
             * Compare CRLs
             *
             * @param {CRL} crl CRL for compare
             * @returns {boolean}
             *
             * @memberOf CRL
             */
            CRL.prototype.equals = function (crl) {
                return this.handle.equals(crl.handle);
            };
            /**
             * Return CRL hash
             *
             * @param {string} [algorithm="sha1"]
             * @returns {String}
             *
             * @memberOf CRL
             */
            CRL.prototype.hash = function (algorithm) {
                if (algorithm === void 0) { algorithm = "sha1"; }
                return this.handle.hash(algorithm).toString("hex");
            };
            /**
             * Return CRL duplicat
             *
             * @returns {CRL}
             *
             * @memberOf CRL
             */
            CRL.prototype.duplicate = function () {
                var crl = new CRL();
                crl.handle = this.handle.duplicate();
                return crl;
            };
            return CRL;
        }(trusted.BaseObject));
        pki.CRL = CRL;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Collection of CRL
         *
         * @export
         * @class CrlCollection
         * @extends {BaseObject<native.PKI.CrlCollection>}
         * @implements {core.ICollectionWrite}
         */
        var CrlCollection = /** @class */ (function (_super) {
            __extends(CrlCollection, _super);
            /**
             * Creates an instance of CrlCollection.
             * @param {native.PKI.CrlCollection} [param]
             *
             * @memberOf CrlCollection
             */
            function CrlCollection(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.CrlCollection) {
                    _this.handle = param;
                }
                else {
                    _this.handle = new native.PKI.CrlCollection();
                }
                return _this;
            }
            /**
             * Return element by index from collection
             *
             * @param {number} index
             * @returns {CRL}
             *
             * @memberOf CrlCollection
             */
            CrlCollection.prototype.items = function (index) {
                return pki.CRL.wrap(this.handle.items(index));
            };
            Object.defineProperty(CrlCollection.prototype, "length", {
                /**
                 * Return collection length
                 *
                 * @readonly
                 * @type {number}
                 * @memberOf CrlCollection
                 */
                get: function () {
                    return this.handle.length();
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Add new element to collection
             *
             * @param {CRL} cert
             *
             * @memberOf CrlCollection
             */
            CrlCollection.prototype.push = function (crl) {
                this.handle.push(crl.handle);
            };
            /**
             * Remove last element from collection
             *
             *
             * @memberOf CrlCollection
             */
            CrlCollection.prototype.pop = function () {
                this.handle.pop();
            };
            /**
             * Remove element by index from collection
             *
             * @param {number} index
             *
             * @memberOf CrlCollection
             */
            CrlCollection.prototype.removeAt = function (index) {
                this.handle.removeAt(index);
            };
            return CrlCollection;
        }(trusted.BaseObject));
        pki.CrlCollection = CrlCollection;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.PEM;
        var DEFAULT_ENC_ALG = trusted.EncryptAlg.GOST_28147;
        /**
         * Encrypt and decrypt operations
         *
         * @export
         * @class Cipher
         * @extends {BaseObject<native.PKI.Cipher>}
         */
        var Cipher = /** @class */ (function (_super) {
            __extends(Cipher, _super);
            /**
             * Creates an instance of Cipher.
             *
             *
             * @memberOf Cipher
             */
            function Cipher() {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKI.Cipher();
                return _this;
            }
            Object.defineProperty(Cipher.prototype, "ProvAlgorithm", {
                /**
                 * Set provider algorithm(GOST)
                 *
                 * @param method gost2001, gost2012_256 or gost2012_512
                 *
                 * @memberOf Cipher
                 */
                set: function (name) {
                    this.handle.setProvAlgorithm(name);
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Encrypt data
             *
             * @param {string} filenameSource This file will encrypted
             * @param {string} filenameEnc File path for save encrypted data
             * @param {EncryptAlg} [alg]
             * @param {DataFormat} [format]
             *
             * @memberOf Cipher
             */
            Cipher.prototype.encrypt = function (filenameSource, filenameEnc, alg, format) {
                if (alg === void 0) { alg = DEFAULT_ENC_ALG; }
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.encrypt(filenameSource, filenameEnc, alg, format);
            };
            /**
             * Encrypt data asynchronously
             *
             * @param {string} filenameSource This file will encrypted
             * @param {string} filenameEnc File path for save encrypted data
             * @param {(msg: string) => void} done Done callback
             * @param {EncryptAlg} [alg]
             * @param {DataFormat} [format]
             *
             * @memberOf Cipher
             */
            Cipher.prototype.encryptAsync = function (filenameSource, filenameEnc, done, alg, format) {
                if (alg === void 0) { alg = DEFAULT_ENC_ALG; }
                if (format === void 0) { format = DEFAULT_DATA_FORMAT; }
                this.handle.encryptAsync(filenameSource, filenameEnc, done, alg, format);
            };
            /**
             * Decrypt data
             *
             * @param {string} filenameEnc This file will decrypt
             * @param {string} filenameDec File path for save decrypted data
             * @param {DataFormat} [format]
             *
             * @memberOf Cipher
             */
            Cipher.prototype.decrypt = function (filenameEnc, filenameDec, format) {
                this.handle.decrypt(filenameEnc, filenameDec, format);
            };
            /**
             * Decrypt data asynchronously
             *
             * @param {string} filenameEnc This file will decrypt
             * @param {string} filenameDec File path for save decrypted data
             * @param {(msg: string) => void} done Done callback
             * @param {DataFormat} [format]
             *
             * @memberOf Cipher
             */
            Cipher.prototype.decryptAsync = function (filenameEnc, filenameDec, done, format) {
                this.handle.decryptAsync(filenameEnc, filenameDec, done, format);
            };
            Object.defineProperty(Cipher.prototype, "recipientsCerts", {
                /**
                 * Add recipients certificates
                 *
                 * @param {CertificateCollection} certs
                 *
                 * @memberOf Cipher
                 */
                set: function (certs) {
                    this.handle.addRecipientsCerts(certs.handle);
                },
                enumerable: true,
                configurable: true
            });
            return Cipher;
        }(trusted.BaseObject));
        pki.Cipher = Cipher;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        var DEFAULT_DATA_FORMAT = trusted.DataFormat.DER;
        /**
         * Wrap PKCS12
         *
         * @export
         * @class PKCS12
         * @extends {BaseObject<native.PKI.PKCS12>}
         */
        var PKCS12 = /** @class */ (function (_super) {
            __extends(PKCS12, _super);
            /**
             * Creates an instance of PKCS12.
             * @param {native.PKI.PKCS12} [param]
             *
             * @memberOf Certificate
             */
            function PKCS12(param) {
                var _this = _super.call(this) || this;
                if (param instanceof native.PKI.PKCS12) {
                    _this.handle = param;
                }
                else {
                    _this.handle = new native.PKI.PKCS12();
                }
                return _this;
            }
            /**
             * Load PKCS12 from file
             *
             * @static
             * @param {string} filename File location
             * @returns {PKCS12}
             *
             * @memberOf PKCS12
             */
            PKCS12.load = function (filename) {
                var pkcs12 = new PKCS12();
                pkcs12.handle.load(filename);
                return pkcs12;
            };
            /**
             * Load PKCS12 from file
             *
             * @param {string} filename File location
             *
             * @memberOf PKCS12
             */
            PKCS12.prototype.load = function (filename) {
                this.handle.load(filename);
            };
            /**
             * Write PKCS12 to file
             *
             * @param {string} filename File location
             *
             * @memberOf PKCS12
             */
            PKCS12.prototype.save = function (filename) {
                this.handle.save(filename);
            };
            return PKCS12;
        }(trusted.BaseObject));
        pki.PKCS12 = PKCS12;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        // Enums values copy from OCSP SDK
        var CPRespStatus;
        (function (CPRespStatus) {
            /// ������ ��������� �������
            CPRespStatus[CPRespStatus["successful"] = 0] = "successful";
            /// ������������ ������
            CPRespStatus[CPRespStatus["malformedRequest"] = 1] = "malformedRequest";
            /// ������ �� ��������� ��-�� ���������� ������
            CPRespStatus[CPRespStatus["internalError"] = 2] = "internalError";
            /// ������ �������� �� ����� ��������, ���������� �����
            CPRespStatus[CPRespStatus["tryLater"] = 3] = "tryLater";
            /// ������ ������ ���� ��������
            CPRespStatus[CPRespStatus["sigRequired"] = 5] = "sigRequired";
            /// ����������� ������� �� ����������� ������������ ����� ������
            CPRespStatus[CPRespStatus["unauthorized"] = 6] = "unauthorized";
            /// ������ ��� ��������� CRL
            CPRespStatus[CPRespStatus["badCRL"] = 8] = "badCRL";
        })(CPRespStatus = pki.CPRespStatus || (pki.CPRespStatus = {}));
        var CPCertStatus;
        (function (CPCertStatus) {
            /// ���������� �� �������
            CPCertStatus[CPCertStatus["Good"] = 0] = "Good";
            /// ���������� �������
            CPCertStatus[CPCertStatus["Revoked"] = 1] = "Revoked";
            /// ������ ����������� ����������
            CPCertStatus[CPCertStatus["Unknown"] = 2] = "Unknown";
        })(CPCertStatus = pki.CPCertStatus || (pki.CPCertStatus = {}));
        var CPCrlReason;
        (function (CPCrlReason) {
            /// �� ���������� ������� ������
            CPCrlReason[CPCrlReason["CRLREASON_UNSPECIFIED"] = 0] = "CRLREASON_UNSPECIFIED";
            /// ���������������� ����������
            CPCrlReason[CPCrlReason["CRLREASON_KEYCOMPROMISE"] = 1] = "CRLREASON_KEYCOMPROMISE";
            /// ����������������� ����� ������������
            CPCrlReason[CPCrlReason["CRLREASON_CACOMPROMISE"] = 2] = "CRLREASON_CACOMPROMISE";
            /// ���������� ��������� � �����������
            CPCrlReason[CPCrlReason["CRLREASON_AFFILIATIONCHANGED"] = 3] = "CRLREASON_AFFILIATIONCHANGED";
            /// ���������� �������
            CPCrlReason[CPCrlReason["CRLREASON_SUPERSEDED"] = 4] = "CRLREASON_SUPERSEDED";
            /// ���������� ������ �� ����� ��� ��� ����� ��� ������� ����������
            CPCrlReason[CPCrlReason["CRLREASON_CESSATIONOFOPERATION"] = 5] = "CRLREASON_CESSATIONOFOPERATION";
            /// �������� ����������� ��������������
            CPCrlReason[CPCrlReason["CRLREASON_CERTIFICATEHOLD"] = 6] = "CRLREASON_CERTIFICATEHOLD";
            /// ������ ��������� �� CRL (������������ ������ � ���������� CRL)
            CPCrlReason[CPCrlReason["CRLREASON_REMOVEFROMCRL"] = 8] = "CRLREASON_REMOVEFROMCRL";
            /// ����������, �������������� ������ ������������ ���� ��������
            CPCrlReason[CPCrlReason["CRLREASON_PRIVILEDGEWITHDRAWN"] = 9] = "CRLREASON_PRIVILEDGEWITHDRAWN";
            /// ����������������� �����, ����������� ���������� �����������
            CPCrlReason[CPCrlReason["CRLREASON_AACOMPROMISE"] = 10] = "CRLREASON_AACOMPROMISE";
        })(CPCrlReason = pki.CPCrlReason || (pki.CPCrlReason = {}));
        /**
         * Wrap OCSP Response and request sending
         *
         * @export
         * @class OCSP
         * @extends {BaseObject<native.PKI.OCSP>}
         */
        var OCSP = /** @class */ (function (_super) {
            __extends(OCSP, _super);
            /**
             * Creates an instance of Ocsp.
             * @param {native.PKI.Certificate | Buffer, native.UTILS.ConnectionSettings?} [param]
             *
             * @memberOf Certificate
             */
            function OCSP(inData, connSettings) {
                var _this = _super.call(this) || this;
                if (inData instanceof pki.Certificate) {
                    _this.handle = new native.PKI.OCSP(inData.handle, (connSettings != undefined) ? connSettings.handle : new native.UTILS.ConnectionSettings());
                }
                else if (inData instanceof Buffer) {
                    _this.handle = new native.PKI.OCSP(inData);
                }
                else if (inData instanceof native.PKI.OCSP) {
                    _this.handle = inData;
                }
                else {
                    throw new TypeError("OCSP::constructor: Wrong input param");
                }
                return _this;
            }
            OCSP.prototype.Export = function () {
                return this.handle.Export();
            };
            /**
             * Verify response signature with specified certificate. If certificate not cpecified, internal certificates used.
             * On success returns 0 and on error returns error code.
             *
             * @param {Certificate} serviceCert
             * @returns {number}
             *
             * @memberOf OCSP
             */
            OCSP.prototype.Verify = function (serviceCert) {
                if (serviceCert instanceof pki.Certificate)
                    return this.handle.Verify(serviceCert.handle);
                return this.handle.Verify();
            };
            OCSP.prototype.VerifyCertificate = function (cert) {
                return this.handle.VerifyCertificate(cert.handle);
            };
            Object.defineProperty(OCSP.prototype, "RespStatus", {
                get: function () {
                    return this.handle.RespStatus();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(OCSP.prototype, "SignatureAlgorithmOid", {
                get: function () {
                    return this.handle.SignatureAlgorithmOid();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(OCSP.prototype, "Certificates", {
                get: function () {
                    return pki.CertificateCollection.wrap(this.handle.Certificates());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(OCSP.prototype, "ProducedAt", {
                get: function () {
                    return new Date(this.handle.ProducedAt());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(OCSP.prototype, "RespNumber", {
                get: function () {
                    return this.handle.RespNumber();
                },
                enumerable: true,
                configurable: true
            });
            OCSP.prototype.RespIndexByCert = function (cert, issuer) {
                return this.handle.RespIndexByCert(cert.handle, (issuer !== undefined) ? issuer.handle : undefined);
            };
            Object.defineProperty(OCSP.prototype, "OcspCert", {
                get: function () {
                    var cert = this.handle.OcspCert();
                    if (cert) {
                        return pki.Certificate.wrap(cert);
                    }
                    else {
                        return undefined;
                    }
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Returns OCSP service certificate. if paraneter certs specified then searched through certificates in collection.
             *
             * @param {CertificateCollection} certs
             * @returns {Certificate}
             *
             * @memberOf OCSP
             */
            OCSP.prototype.getOcspCert = function (certs) {
                var cert = undefined;
                if (certs instanceof pki.CertificateCollection) {
                    cert = this.handle.getOcspCert(certs.handle);
                }
                else {
                    cert = this.handle.getOcspCert();
                }
                if (cert) {
                    return pki.Certificate.wrap(cert);
                }
                else {
                    return undefined;
                }
            };
            OCSP.prototype.Status = function (respIdx) {
                if (respIdx === undefined)
                    return this.handle.Status();
                return this.handle.Status(respIdx);
            };
            OCSP.prototype.RevTime = function (respIdx) {
                if (respIdx === undefined)
                    return new Date(this.handle.RevTime());
                return new Date(this.handle.RevTime(respIdx));
            };
            OCSP.prototype.RevReason = function (respIdx) {
                if (respIdx === undefined)
                    return this.handle.RevReason();
                return this.handle.RevReason(respIdx);
            };
            OCSP.prototype.ThisUpdate = function (respIdx) {
                if (respIdx === undefined)
                    return new Date(this.handle.ThisUpdate());
                return new Date(this.handle.ThisUpdate(respIdx));
            };
            /**
             * Return date of Next Update. Field is optional. To verify returned date value call getTime() method on it. If getTime returns 0 than Nextupdate property is empty and should not be used.
             *
             * @readonly
             * @param {number} [respIdx] Response index. Default value is 0.
             * @type {Date}
             * @memberOf OCSP
             */
            OCSP.prototype.NextUpdate = function (respIdx) {
                var nextUpdate;
                if (respIdx === undefined) {
                    nextUpdate = this.handle.NextUpdate();
                }
                else {
                    nextUpdate = this.handle.NextUpdate(respIdx);
                }
                if ("" === nextUpdate) {
                    return new Date(0);
                }
                return new Date(nextUpdate);
            };
            return OCSP;
        }(trusted.BaseObject));
        pki.OCSP = OCSP;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pki;
    (function (pki) {
        /**
         * Wrap TSPRequest utility object for hashing data before request sending
         *
         * @export
         * @class TSPRequest
         * @extends {BaseObject<native.PKI.TSPRequest>}
         */
        var TSPRequest = /** @class */ (function (_super) {
            __extends(TSPRequest, _super);
            /**
             * Creates an instance of Tsp Request.
             * @param {hashAlgOid: string, dataFileName?: string} [param]
             *
             * @memberOf TSPRequest
             */
            function TSPRequest(hashAlgOid, dataFileName) {
                var _this = _super.call(this) || this;
                if (dataFileName != undefined) {
                    _this.handle = new native.PKI.TSPRequest(hashAlgOid, dataFileName);
                }
                else {
                    _this.handle = new native.PKI.TSPRequest(hashAlgOid);
                }
                return _this;
            }
            TSPRequest.prototype.AddData = function (data) {
                this.handle.AddData(data);
            };
            Object.defineProperty(TSPRequest.prototype, "CertReq", {
                get: function () {
                    return this.handle.GetCertReq();
                },
                set: function (certReq) {
                    this.handle.SetCertReq(certReq);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSPRequest.prototype, "Nonce", {
                get: function () {
                    return this.handle.GetNonce();
                },
                set: function (nonce) {
                    this.handle.SetNonce(nonce);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSPRequest.prototype, "PolicyId", {
                get: function () {
                    return this.handle.GetPolicyId();
                },
                set: function (policyId) {
                    this.handle.SetPolicyId(policyId);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSPRequest.prototype, "HashAlgOid", {
                get: function () {
                    return this.handle.GetHashAlgOid();
                },
                set: function (hashAlgOid) {
                    this.handle.SetHashAlgOid(hashAlgOid);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSPRequest.prototype, "DataHash", {
                get: function () {
                    return this.handle.GetDataHash();
                },
                set: function (dataHash) {
                    this.handle.SetDataHash(dataHash);
                },
                enumerable: true,
                configurable: true
            });
            return TSPRequest;
        }(trusted.BaseObject));
        pki.TSPRequest = TSPRequest;
        /**
         * Wrap TSP timestamp object and request sending
         *
         * @export
         * @class TSP
         * @extends {BaseObject<native.PKI.TSP>}
         */
        var TSP = /** @class */ (function (_super) {
            __extends(TSP, _super);
            /**
             * Creates an instance of Tsp.
             * @param {Buffer, native.UTILS.ConnectionSettings?} [param]
             *
             * @memberOf TSP
             */
            function TSP(inData, connSettings) {
                var _this = _super.call(this) || this;
                if (inData instanceof Buffer) {
                    _this.handle = new native.PKI.TSP(inData);
                }
                else if ((inData instanceof trusted.pki.TSPRequest)
                    && (connSettings instanceof trusted.utils.ConnectionSettings)) {
                    _this.handle = new native.PKI.TSP(inData.handle, connSettings.handle);
                }
                else if (inData instanceof native.PKI.TSP) {
                    _this.handle = inData;
                }
                else {
                    throw new TypeError("TSP::constructor: Wrong input param");
                }
                return _this;
            }
            TSP.prototype.Export = function () {
                return this.handle.Export();
            };
            Object.defineProperty(TSP.prototype, "Certificates", {
                get: function () {
                    return pki.CertificateCollection.wrap(this.handle.Certificates());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "TSACertificate", {
                get: function () {
                    return pki.Certificate.wrap(this.handle.TSACertificate());
                },
                enumerable: true,
                configurable: true
            });
            TSP.prototype.Verify = function () {
                return this.handle.Verify();
            };
            TSP.prototype.VerifyCertificate = function (cert) {
                return this.handle.VerifyCertificate(cert.handle);
            };
            Object.defineProperty(TSP.prototype, "FailInfo", {
                get: function () {
                    return this.handle.FailInfo();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "Status", {
                get: function () {
                    return this.handle.Status();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "StatusString", {
                get: function () {
                    return this.handle.StatusString();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "DataHashAlgOID", {
                get: function () {
                    return this.handle.DataHashAlgOID();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "DataHash", {
                get: function () {
                    return this.handle.DataHash();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "PolicyID", {
                get: function () {
                    return this.handle.PolicyID();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "SerialNumber", {
                get: function () {
                    return this.handle.SerialNumber();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "Time", {
                get: function () {
                    return new Date(this.handle.Time());
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "Accuracy", {
                get: function () {
                    return this.handle.Accuracy();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "Ordering", {
                get: function () {
                    return this.handle.Ordering();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "HasNonce", {
                get: function () {
                    return this.handle.HasNonce();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "TsaName", {
                get: function () {
                    return this.handle.TsaName();
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(TSP.prototype, "TsaNameBlob", {
                get: function () {
                    return this.handle.TsaNameBlob();
                },
                enumerable: true,
                configurable: true
            });
            return TSP;
        }(trusted.BaseObject));
        pki.TSP = TSP;
    })(pki = trusted.pki || (trusted.pki = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pkistore;
    (function (pkistore) {
        /**
         * Work with json files
         *
         * @export
         * @class CashJson
         * @extends {BaseObject<native.PKISTORE.CashJson>}
         */
        var CashJson = /** @class */ (function (_super) {
            __extends(CashJson, _super);
            /**
             * Creates an instance of CashJson.
             *
             * @param {string} fileName File path
             *
             * @memberOf CashJson
             */
            function CashJson(fileName) {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKISTORE.CashJson(fileName);
                return _this;
            }
            /**
             * Return PkiItems from json
             *
             * @returns {native.PKISTORE.IPkiItem[]}
             *
             * @memberOf CashJson
             */
            CashJson.prototype.export = function () {
                return this.handle.export();
            };
            /**
             * Import PkiItems to json
             *
             * @param {native.PKISTORE.IPkiItem[]} items
             *
             * @memberOf CashJson
             */
            CashJson.prototype.import = function (items) {
                for (var _i = 0, items_1 = items; _i < items_1.length; _i++) {
                    var item = items_1[_i];
                    var pkiItem = new pkistore.PkiItem();
                    pkiItem.format = item.format;
                    pkiItem.type = item.type;
                    pkiItem.category = item.category;
                    pkiItem.provider = item.provider;
                    pkiItem.uri = item.uri;
                    pkiItem.hash = item.hash.toLocaleLowerCase();
                    if (item.subjectName) {
                        pkiItem.subjectName = item.subjectName;
                    }
                    if (item.subjectFriendlyName) {
                        pkiItem.subjectFriendlyName = item.subjectFriendlyName;
                    }
                    if (item.issuerName) {
                        pkiItem.issuerName = item.issuerName;
                    }
                    if (item.issuerFriendlyName) {
                        pkiItem.issuerFriendlyName = item.issuerFriendlyName;
                    }
                    if (item.serial) {
                        pkiItem.serial = item.serial;
                    }
                    if (item.notBefore) {
                        pkiItem.notBefore = item.notBefore;
                    }
                    if (item.notAfter) {
                        pkiItem.notAfter = item.notAfter;
                    }
                    if (item.lastUpdate) {
                        pkiItem.lastUpdate = item.lastUpdate;
                    }
                    if (item.nextUpdate) {
                        pkiItem.nextUpdate = item.nextUpdate;
                    }
                    if (item.authorityKeyid) {
                        pkiItem.authorityKeyid = item.authorityKeyid;
                    }
                    if (item.crlNumber) {
                        pkiItem.crlNumber = item.crlNumber;
                    }
                    if (item.key) {
                        pkiItem.key = item.key;
                    }
                    if (item.encrypted) {
                        pkiItem.keyEnc = item.encrypted;
                    }
                    if (item.organizationName) {
                        pkiItem.organizationName = item.organizationName;
                    }
                    if (item.signatureAlgorithm) {
                        pkiItem.signatureAlgorithm = item.signatureAlgorithm;
                    }
                    if (item.signatureDigestAlgorithm) {
                        pkiItem.signatureDigestAlgorithm = item.signatureDigestAlgorithm;
                    }
                    this.handle.import(pkiItem.handle);
                }
            };
            return CashJson;
        }(trusted.BaseObject));
        pkistore.CashJson = CashJson;
    })(pkistore = trusted.pkistore || (trusted.pkistore = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var pkistore;
    (function (pkistore) {
        /**
         * Support CryptoPro provider
         *
         * @export
         * @class ProviderCryptopro
         * @extends {BaseObject<native.PKISTORE.ProviderCryptopro>}
         */
        var ProviderCryptopro = /** @class */ (function (_super) {
            __extends(ProviderCryptopro, _super);
            function ProviderCryptopro() {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKISTORE.ProviderCryptopro();
                return _this;
            }
            /**
            * Ensure that the certificate's private key is available
            *
            * @static
            * @param {Certificate} cert
            * @returns {boolean}
            * @memberOf ProviderCryptopro
            */
            ProviderCryptopro.prototype.hasPrivateKey = function (cert) {
                return this.handle.hasPrivateKey(cert.handle);
            };
            return ProviderCryptopro;
        }(trusted.BaseObject));
        pkistore.ProviderCryptopro = ProviderCryptopro;
    })(pkistore = trusted.pkistore || (trusted.pkistore = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
/* tslint:disable:max-classes-per-file */
var trusted;
(function (trusted) {
    var pkistore;
    (function (pkistore) {
        /**
         * Filter for search objects
         *
         * @export
         * @class Filter
         * @extends {BaseObject<native.PKISTORE.Filter>}
         * @implements {native.PKISTORE.IFilter}
         */
        var Filter = /** @class */ (function (_super) {
            __extends(Filter, _super);
            function Filter() {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKISTORE.Filter();
                return _this;
            }
            Object.defineProperty(Filter.prototype, "types", {
                set: function (type) {
                    this.handle.setType(type);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "providers", {
                set: function (provider) {
                    this.handle.setProvider(provider);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "categorys", {
                set: function (category) {
                    this.handle.setCategory(category);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "hash", {
                set: function (hash) {
                    this.handle.setHash(hash);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "subjectName", {
                set: function (subjectName) {
                    this.handle.setSubjectName(subjectName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "subjectFriendlyName", {
                set: function (subjectFriendlyName) {
                    this.handle.setSubjectFriendlyName(subjectFriendlyName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "issuerName", {
                set: function (issuerName) {
                    this.handle.setIssuerName(issuerName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "issuerFriendlyName", {
                set: function (issuerFriendlyName) {
                    this.handle.setIssuerFriendlyName(issuerFriendlyName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(Filter.prototype, "serial", {
                set: function (serial) {
                    this.handle.setSerial(serial);
                },
                enumerable: true,
                configurable: true
            });
            return Filter;
        }(trusted.BaseObject));
        pkistore.Filter = Filter;
        /**
         * Wrap pki objects (certificate, key, crl, csr)
         *
         * @export
         * @class PkiItem
         * @extends {BaseObject<native.PKISTORE.PkiItem>}
         * @implements {native.PKISTORE.IPkiItem}
         */
        var PkiItem = /** @class */ (function (_super) {
            __extends(PkiItem, _super);
            /**
             * Creates an instance of PkiItem.
             *
             *
             * @memberOf PkiItem
             */
            function PkiItem() {
                var _this = _super.call(this) || this;
                _this.handle = new native.PKISTORE.PkiItem();
                return _this;
            }
            Object.defineProperty(PkiItem.prototype, "format", {
                set: function (format) {
                    this.handle.setFormat(format);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "type", {
                set: function (type) {
                    this.handle.setType(type);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "provider", {
                set: function (provider) {
                    this.handle.setProvider(provider);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "category", {
                set: function (category) {
                    this.handle.setCategory(category);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "uri", {
                set: function (uri) {
                    this.handle.setURI(uri);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "hash", {
                set: function (hash) {
                    this.handle.setHash(hash);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "subjectName", {
                set: function (subjectName) {
                    this.handle.setSubjectName(subjectName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "subjectFriendlyName", {
                set: function (subjectFriendlyName) {
                    this.handle.setSubjectFriendlyName(subjectFriendlyName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "issuerName", {
                set: function (issuerName) {
                    this.handle.setIssuerName(issuerName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "issuerFriendlyName", {
                set: function (issuerFriendlyName) {
                    this.handle.setIssuerFriendlyName(issuerFriendlyName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "serial", {
                set: function (serial) {
                    this.handle.setSerial(serial);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "notBefore", {
                set: function (before) {
                    this.handle.setNotBefore(before);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "notAfter", {
                set: function (after) {
                    this.handle.setNotAfter(after);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "lastUpdate", {
                set: function (lastUpdate) {
                    this.handle.setLastUpdate(lastUpdate);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "nextUpdate", {
                set: function (nextUpdate) {
                    this.handle.setNextUpdate(nextUpdate);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "authorityKeyid", {
                set: function (authorityKeyid) {
                    this.handle.setAuthorityKeyid(authorityKeyid);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "crlNumber", {
                set: function (crlNumber) {
                    this.handle.setCrlNumber(crlNumber);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "key", {
                set: function (key) {
                    this.handle.setKey(key);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "keyEnc", {
                set: function (enc) {
                    this.handle.setKeyEncrypted(enc);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "organizationName", {
                set: function (organizationName) {
                    this.handle.setOrganizationName(organizationName);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "signatureAlgorithm", {
                set: function (signatureAlgorithm) {
                    this.handle.setSignatureAlgorithm(signatureAlgorithm);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "signatureDigestAlgorithm", {
                set: function (signatureDigestAlgorithm) {
                    this.handle.setSignatureAlgorithm(signatureDigestAlgorithm);
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(PkiItem.prototype, "publicKeyAlgorithm", {
                set: function (publicKeyAlgorithm) {
                    this.handle.setPublicKeyAlgorithm(publicKeyAlgorithm);
                },
                enumerable: true,
                configurable: true
            });
            return PkiItem;
        }(trusted.BaseObject));
        pkistore.PkiItem = PkiItem;
        var PkiStore = /** @class */ (function (_super) {
            __extends(PkiStore, _super);
            /**
             * Creates an instance of PkiStore.
             * @param {(native.PKISTORE.PkiStore | string)} param
             *
             * @memberOf PkiStore
             */
            function PkiStore(param) {
                var _this = _super.call(this) || this;
                if (typeof (param) === "string") {
                    _this.handle = new native.PKISTORE.PkiStore(param);
                    try {
                        _this.cashJson = new pkistore.CashJson(param);
                    }
                    catch (e) {
                        //
                    }
                }
                else if (param instanceof native.PKISTORE.PkiStore) {
                    _this.handle = param;
                }
                else {
                    throw new TypeError("PkiStore::constructor: Wrong input param");
                }
                return _this;
            }
            Object.defineProperty(PkiStore.prototype, "cash", {
                /**
                 * Return cash json
                 *
                 * @readonly
                 * @type {CashJson}
                 * @memberOf PkiStore
                 */
                get: function () {
                    return this.cashJson;
                },
                enumerable: true,
                configurable: true
            });
            /**
             * Add provider (system, microsoft | cryptopro)
             *
             * @param {native.PKISTORE.Provider} provider
             *
             * @memberOf PkiStore
             */
            PkiStore.prototype.addProvider = function (provider) {
                this.handle.addProvider(provider);
            };
            /**
             * Find items in local store
             *
             * @param {native.PKISTORE.IFilter} [ifilter]
             * @returns {native.PKISTORE.IPkiItem[]}
             *
             * @memberOf PkiStore
             */
            PkiStore.prototype.find = function (ifilter) {
                var filter = new Filter();
                if (!ifilter) {
                    return this.handle.find(filter.handle);
                }
                if (ifilter.type) {
                    for (var _i = 0, _a = ifilter.type; _i < _a.length; _i++) {
                        var type = _a[_i];
                        filter.types = type;
                    }
                }
                if (ifilter.provider) {
                    for (var _b = 0, _c = ifilter.provider; _b < _c.length; _b++) {
                        var provider = _c[_b];
                        filter.providers = provider;
                    }
                }
                if (ifilter.category) {
                    for (var _d = 0, _e = ifilter.category; _d < _e.length; _d++) {
                        var category = _e[_d];
                        filter.categorys = category;
                    }
                }
                if (ifilter.hash) {
                    filter.hash = ifilter.hash;
                }
                if (ifilter.subjectName) {
                    filter.subjectName = ifilter.subjectName;
                }
                if (ifilter.subjectFriendlyName) {
                    filter.subjectFriendlyName = ifilter.subjectFriendlyName;
                }
                if (ifilter.issuerName) {
                    filter.issuerName = ifilter.issuerName;
                }
                if (ifilter.issuerFriendlyName) {
                    filter.issuerFriendlyName = ifilter.issuerFriendlyName;
                }
                if (ifilter.serial) {
                    filter.serial = ifilter.serial;
                }
                return this.handle.find(filter.handle);
            };
            /**
             * Find key in local store
             *
             * @param {native.PKISTORE.IFilter} ifilter
             * @returns {native.PKISTORE.IPkiItem}
             *
             * @memberOf PkiStore
             */
            PkiStore.prototype.findKey = function (ifilter) {
                var filter = new Filter();
                if (ifilter.type) {
                    for (var _i = 0, _a = ifilter.type; _i < _a.length; _i++) {
                        var type = _a[_i];
                        filter.types = type;
                    }
                }
                if (ifilter.provider) {
                    for (var _b = 0, _c = ifilter.provider; _b < _c.length; _b++) {
                        var provider = _c[_b];
                        filter.providers = provider;
                    }
                }
                if (ifilter.category) {
                    for (var _d = 0, _e = ifilter.category; _d < _e.length; _d++) {
                        var category = _e[_d];
                        filter.categorys = category;
                    }
                }
                if (ifilter.hash) {
                    filter.hash = ifilter.hash;
                }
                if (ifilter.subjectName) {
                    filter.subjectName = ifilter.subjectName;
                }
                if (ifilter.subjectFriendlyName) {
                    filter.subjectFriendlyName = ifilter.subjectFriendlyName;
                }
                if (ifilter.issuerName) {
                    filter.issuerName = ifilter.issuerName;
                }
                if (ifilter.issuerFriendlyName) {
                    filter.issuerFriendlyName = ifilter.issuerFriendlyName;
                }
                if (ifilter.serial) {
                    filter.serial = ifilter.serial;
                }
                return this.handle.findKey(filter.handle);
            };
            /**
             * Return pki object (certificate, crl, request, key) by PkiItem
             *
             * @param {native.PKISTORE.IPkiItem} item
             * @returns {*}
             *
             * @memberOf PkiStore
             */
            PkiStore.prototype.getItem = function (item) {
                var pkiItem = new PkiItem();
                pkiItem.format = item.format;
                pkiItem.type = item.type;
                pkiItem.category = item.category;
                pkiItem.provider = item.provider;
                pkiItem.uri = item.uri;
                pkiItem.hash = item.hash;
                if (item.subjectName) {
                    pkiItem.subjectName = item.subjectName;
                }
                if (item.subjectFriendlyName) {
                    pkiItem.subjectFriendlyName = item.subjectFriendlyName;
                }
                if (item.issuerName) {
                    pkiItem.issuerName = item.issuerName;
                }
                if (item.issuerFriendlyName) {
                    pkiItem.issuerFriendlyName = item.issuerFriendlyName;
                }
                if (item.serial) {
                    pkiItem.serial = item.serial;
                }
                if (item.notBefore) {
                    pkiItem.notBefore = item.notBefore;
                }
                if (item.notAfter) {
                    pkiItem.notAfter = item.notAfter;
                }
                if (item.lastUpdate) {
                    pkiItem.lastUpdate = item.lastUpdate;
                }
                if (item.nextUpdate) {
                    pkiItem.nextUpdate = item.nextUpdate;
                }
                if (item.authorityKeyid) {
                    pkiItem.authorityKeyid = item.authorityKeyid;
                }
                if (item.crlNumber) {
                    pkiItem.crlNumber = item.crlNumber;
                }
                if (item.key) {
                    pkiItem.key = item.key;
                }
                if (item.encrypted) {
                    pkiItem.keyEnc = item.encrypted;
                }
                if (item.organizationName) {
                    pkiItem.organizationName = item.organizationName;
                }
                if (item.signatureAlgorithm) {
                    pkiItem.signatureAlgorithm = item.signatureAlgorithm;
                }
                if (item.signatureDigestAlgorithm) {
                    pkiItem.signatureDigestAlgorithm = item.signatureDigestAlgorithm;
                }
                if (item.publicKeyAlgorithm) {
                    pkiItem.publicKeyAlgorithm = item.publicKeyAlgorithm;
                }
                if (item.type === "CERTIFICATE") {
                    return trusted.pki.Certificate.wrap(this.handle.getItem(pkiItem.handle));
                }
                if (item.type === "CRL") {
                    return trusted.pki.CRL.wrap(this.handle.getItem(pkiItem.handle));
                }
            };
            Object.defineProperty(PkiStore.prototype, "certs", {
                get: function () {
                    return new trusted.pki.CertificateCollection(this.handle.getCerts());
                },
                enumerable: true,
                configurable: true
            });
            /**
            * Import certificste to local store
            *
            * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
            * @param {string} category MY, OTHERS, TRUST, CRL
            * @param {Certificate} cert Certificate
            * @param {string} [contName] optional set container name
            * @param {number} [provType]
            * @returns {string}
            *
            * @memberOf PkiStore
            */
            PkiStore.prototype.addCert = function (provider, category, cert, contName, provType) {
                return this.handle.addCert(provider, category, cert.handle, contName, provType);
            };
            /**
            * Import CRL to local store
            *
            * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
            * @param {string} category MY, OTHERS, TRUST, CRL
            * @param {CRL} crl CRL
            * @returns {string}
            *
            * @memberOf PkiStore
            */
            PkiStore.prototype.addCrl = function (provider, category, crl) {
                return this.handle.addCrl(provider, category, crl.handle);
            };
            /**
            * Delete certificste from store
            *
            * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
            * @param {string} category MY, OTHERS, TRUST, CRL
            * @param {Certificate} cert Certificate
            * @returns
            *
            * @memberOf PkiStore
            */
            PkiStore.prototype.deleteCert = function (provider, category, cert) {
                return this.handle.deleteCert(provider, category, cert.handle);
            };
            /**
            * Delete CRL from store
            *
            * @param {native.PKISTORE.Provider} provider
            * @param {string} category
            * @param {pki.Crl} crl
            * @returns {void}
            * @memberof PkiStore
            */
            PkiStore.prototype.deleteCrl = function (provider, category, crl) {
                return this.handle.deleteCrl(provider, category, crl.handle);
            };
            return PkiStore;
        }(trusted.BaseObject));
        pkistore.PkiStore = PkiStore;
    })(pkistore = trusted.pkistore || (trusted.pkistore = {}));
})(trusted || (trusted = {}));
var trusted;
(function (trusted) {
    /**
     *
     * @export
     * @enum {number}
     */
    var LoggerLevel;
    (function (LoggerLevel) {
        LoggerLevel[LoggerLevel["NULL"] = 0] = "NULL";
        LoggerLevel[LoggerLevel["ERROR"] = 1] = "ERROR";
        LoggerLevel[LoggerLevel["WARNING"] = 2] = "WARNING";
        LoggerLevel[LoggerLevel["INFO"] = 4] = "INFO";
        LoggerLevel[LoggerLevel["DEBUG"] = 8] = "DEBUG";
        LoggerLevel[LoggerLevel["TRACE"] = 16] = "TRACE";
        LoggerLevel[LoggerLevel["CryptoPro"] = 32] = "CryptoPro";
        // tslint:disable-next-line:no-bitwise
        LoggerLevel[LoggerLevel["ALL"] = 63] = "ALL";
    })(LoggerLevel = trusted.LoggerLevel || (trusted.LoggerLevel = {}));
})(trusted || (trusted = {}));
/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
var trusted;
(function (trusted) {
    var common;
    (function (common) {
        var DEFAULT_LOGGER_LEVEL = trusted.LoggerLevel.ALL;
        /**
         * Wrap logger class
         *
         * @export
         * @class Logger
         * @extends {BaseObject<native.COMMON.Logger>}
         */
        var Logger = /** @class */ (function (_super) {
            __extends(Logger, _super);
            /**
             * Creates an instance of Logger.
             *
             * @memberOf Logger
             */
            function Logger() {
                var _this = _super.call(this) || this;
                _this.handle = new native.COMMON.Logger();
                return _this;
            }
            /**
             * Start write log to a file
             *
             * @static
             * @param {string} filename
             * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
             * @returns {Logger}
             *
             * @memberOf Logger
             */
            Logger.start = function (filename, level) {
                if (level === void 0) { level = DEFAULT_LOGGER_LEVEL; }
                var logger = new Logger();
                logger.handle.start(filename, level);
                return logger;
            };
            /**
             * Start write log to a file
             *
             * @param {string} filename
             * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
             * @returns {void}
             *
             * @memberOf Logger
             */
            Logger.prototype.start = function (filename, level) {
                if (level === void 0) { level = DEFAULT_LOGGER_LEVEL; }
                return this.handle.start(filename, level);
            };
            /**
             * Stop write log file
             *
             * @returns {void}
             *
             * @memberOf Logger
             */
            Logger.prototype.stop = function () {
                return this.handle.stop();
            };
            /**
             * Clean exsisting log file
             *
             * @returns {void}
             *
             * @memberOf Logger
             */
            Logger.prototype.clear = function () {
                return this.handle.clear();
            };
            return Logger;
        }(trusted.BaseObject));
        common.Logger = Logger;
    })(common = trusted.common || (trusted.common = {}));
})(trusted || (trusted = {}));
var trusted;
module.exports = trusted;
var native = undefined;
try {
    native = require("../build/Release/trusted-cades.node");
}
catch (e) {
    native = require("../build/Release/trusted.node");
}
//# sourceMappingURL=trusted.js.map