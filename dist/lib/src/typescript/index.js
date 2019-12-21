"use strict";
exports.__esModule = true;
// try to use secp256k1, fallback to browser implementation
try {
    module.exports = require("./node");
}
catch (e) {
    if (process.env.ECCRYPTO_NO_FALLBACK) {
        throw e;
    }
    else {
        module.exports = require("./browser");
    }
}
