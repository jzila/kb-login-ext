var exports = module.exports = {};

var http = require("http"),
	https = require("https"),
	assert = require("assert"),
	kbpgp = require("kbpgp"),
	crypto = require("crypto"),
	util = require("../lib/util.js");

var pkey_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?usernames={0}&fields=basics,profile,public_keys";

var validateBlob = function (blob) {
	// TODO Issue #3 make this actually validate the token we sent
	return blob.siteId && blob.kb_post_url && blob.token && blob.token.length >= 85;
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
					try {
						assert.deepEqual(blobFromSignature, blob);
						cb(200, {
							status: {code: 0, name: "OK"},
							user: {
								kb_username: user.basics.username,
								kb_uid: user.id,
								full_name: user.profile.full_name,
								location: user.profile.location,
								token: blob.token
							}
						});
					} catch (Error) {
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
		console.log("lookup callback");
		var body = '';

		response.on('data', function (chunk) {
			console.log("lookup data");
			body += chunk;
		});

		response.on('end', function () {
			console.log("lookup end");
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
			}
		});
	};

	var lookupUrl = util.formatString(pkey_url, blob.email_or_username);
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
