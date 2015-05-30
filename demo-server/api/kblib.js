var exports = module.exports = {};

var http = require("http"),
	https = require("https"),
	assert = require("assert"),
	crypto = require("crypto"),
	async = require('asyncawait/async'),
	await = require('asyncawait/await'),
	Promise = require('bluebird'),
	util = require("../lib/util.js");
var kbpgp = Promise.promisifyAll(require("kbpgp"));

var pkey_username_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?usernames={0}&fields=basics,profile,public_keys";
var pkey_fingerprint_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?key_fingerprint={0}&fields=basics,profile,public_keys";

var validateBlob = function (blob) {
	return blob.siteId && blob.token && blob.token.length >= 85;
};

var validateSignature = function (blob, blobFromSignature) {
    var keys = [
        "siteId",
        "token",
        "email_or_username",
        "fingerprint",
        "kb_login_ext_nonce",
        "kb_login_ext_annotation"
    ];

    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (blob[k] !== blobFromSignature[k]) {
            return false;
        }
    }
    return true;
};

var validatePublicData = function(publicData) {
    return publicData &&
           publicData.status &&
           publicData.status.name === "OK" &&
           publicData.them &&
           publicData.them.length &&
           publicData.them[0].public_keys &&
           publicData.them[0].public_keys.primary &&
           publicData.them[0].public_keys.primary.bundle;
};

var handleKbCertVerify = async(function(publicData, blob, signature, cb) {
    try {
        if (!validatePublicData(publicData)) {
            throw "Error obtaining matching public key";
        }
        var user = publicData.them[0];
        var kms, km, ring, literals;
        try {
            kms = await(kbpgp.KeyManager.import_from_armored_pgpAsync({armored: user.public_keys.primary.bundle}));
        } catch (err) {
            throw "Unable to load public key";
        }
        if (!kms) {
            throw "Unable to load key manager";
        }
        km = kms[0];
        ring = new kbpgp.keyring.KeyRing;
        ring.add_key_managerAsync(km);
        try {
            literals = await(kbpgp.unboxAsync({keyfetch: ring, armored: signature}));
        } catch(err) {
            throw "Unable to verify signature";
        }
        var decryptedSignature = literals[0].toString();
        var blobFromSignature = JSON.parse(decryptedSignature);
        if (!validateSignature(blob, blobFromSignature)) {
            throw "Mismatched blob and signature";
        }
        var user_name = "",
            location = "";
        if (user['profile']) {
            var profile = user['profile'];
            user_name = profile['full_name'] || user_name;
            location = profile['location'] || location;
        }
        cb(200, {
            status: {code: 0, name: "OK"},
            user: {
                kb_username: user['basics']['username'],
                kb_uid: user['id'],
                full_name: user_name,
                location: location,
                token: blob.token
            }
        });
    } catch (err) {
        console.log("Error: " + err);
        cb(400, err);
    }
});

exports.kbCertVerify = function (blob, signature, cb) {
	if (!validateBlob(blob)) {
		console.log("Signature blob not valid");
		return cb(400, "Invalid invalid signature blob");
	}

	var lookupCallback = function (response) {
		var body = '';

		response.on('data', function (chunk) {
			body += chunk;
		});

		response.on('end', function () {
            var publicData = JSON.parse(body);
            handleKbCertVerify(publicData, blob, signature, cb);
		});
	};

	var lookupUrl;
	if (blob.fingerprint) {
		lookupUrl = util.formatString(pkey_fingerprint_url, blob.fingerprint);
	} else {
		lookupUrl = util.formatString(pkey_username_url, blob.email_or_username);
	}
	https.get(lookupUrl, lookupCallback);
};

exports.getBlob = function (siteId, cb) {
	var random = crypto.randomBytes(64).toString('base64');
	var blob = {
		siteId: siteId,
		token: random
	};
	cb(200, blob);
};
