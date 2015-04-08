var exports = module.exports = {};

var http = require("http"),
	https = require("https"),
	assert = require("assert"),
	kbpgp = require("kbpgp"),
	crypto = require("crypto"),
	util = require("../lib/util.js");

var pkey_username_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?usernames={0}&fields=basics,profile,public_keys";
var pkey_fingerprint_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?key_fingerprint={0}&fields=basics,profile,public_keys";

var validateBlob = function (blob) {
	return blob.siteId && blob.kb_post_url && blob.token && blob.token.length >= 85;
};

var validateSignature = function (blob, blobFromSignature) {
    var keys = [
        "siteId",
        "token",
        "kb_post_url",
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

var makeKeyManagerCallback = function (blob, signature, user, cb) {
	return function (err, km) {
		if (!err && km) {
			var ring = new kbpgp.keyring.KeyRing;
			ring.add_key_manager(km);
			kbpgp.unbox({keyfetch: ring, armored: signature }, function (err, literals) {
				if (!err) {
					var decryptedSignature = literals[0].toString();
					var blobFromSignature = JSON.parse(decryptedSignature);
                    if (validateSignature(blob, blobFromSignature)) {
                        var user_name = "Unknown Name";
                        var location = "Unknown Location";
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
                    } else {
						cb(400, "Mismatched blob and signature");
                    }
				} else {
					cb(400, "Unable to verify signature");
				}
			});
		} else {
			cb(400, "Unable to load public key");
		}
	};
};

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
			if (publicData &&
				publicData.status &&
				publicData.status.name === "OK" &&
				publicData.them &&
				publicData.them.length &&
				publicData.them[0].public_keys &&
				publicData.them[0].public_keys.primary &&
				publicData.them[0].public_keys.primary.bundle) {
				var user = publicData.them[0];
				kbpgp.KeyManager.import_from_armored_pgp(
					{armored: user.public_keys.primary.bundle},
					makeKeyManagerCallback(blob, signature, user, cb)
				);
			} else {
				cb(400, "Error obtaining matching public key");
			}
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

exports.getBlob = function (siteId, verify_url, cb) {
	var random = crypto.randomBytes(64).toString('base64');
	var blob = {
		siteId: siteId,
		token: random,
		kb_post_url: verify_url
	};
	cb(200, blob);
};
