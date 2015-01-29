var nodeStatic = require("node-static"),
	http = require("http"),
	https = require("https"),
	assert = require("assert"),
	journey = require("journey"),
	kbpgp = require("kbpgp");

var pkey_url = "https://keybase.io:443/_/api/1.0/user/lookup.json?usernames={0}&fields=basics,profile,public_keys";
var port = process.env.PORT;

var router = new journey.Router();
var fileServer = new nodeStatic.Server("./static");

function formatString(format) {
	var args = Array.prototype.slice.call(arguments, 1);
	return format.replace(/{(\d+)}/g, function(match, number) {
		return typeof args[number] != 'undefined' ? args[number] : match;
	});
}

function validateBlob(blob) {
	return blob.siteId && blob.kb_post_url && blob.nonce && blob.nonce.length >= 32;
}

function createKeyManagerCallback(resp, blob, signature, user) {
	return function(err, km) {
		if (!err && km) {
			var ring = new kbpgp.keyring.KeyRing;
			ring.add_key_manager(km);
			kbpgp.unbox({keyfetch: ring, armored: signature }, function(err, literals) {
				if (!err) {
					var asString = literals[0].toString();
					var asObject = JSON.parse(asString);
					try {
						assert.deepEqual(asObject, blob);
						resp.send(200, {"Content-Type": "application/json"}, {
							status: {code: 0, name: "OK"},
							user: {
								kb_username: user.basics.username,
								kb_uid: user.id,
								full_name: user.profile.full_name,
								location: user.profile.location
							}
						});
					} catch (Error) {
						resp.send(400, "Mismatched blob and signature");
					}
				} else {
					resp.send(400, "Unable to verify signature");
				}
			});
		} else {
			resp.send(400, "Unable to load public key");
		}
	}
}

function kbCertVerify(req, resp, data) {
	if (!data.blob || !data.signature) {
		console.log("Signature data not valid");
		return resp.send(400, "Invalid signature data");
	}
	var signature = data.signature;
	var blob = JSON.parse(data.blob);

	if (!validateBlob(blob)) {
		console.log("Signature blob not valid");
		return resp.send(400, "Invalid invalid signature blob");
	}

	var lookupCallback = function(response) {
		console.log("lookup callback");
		var body = '';

		response.on('data', function(chunk) {
			console.log("lookup data");
			body += chunk;
		});

		response.on('end', function() {
			console.log("lookup end");
			var publicData = JSON.parse(body);
			if (publicData &&
				publicData.status &&
				publicData.status.name=="OK" &&
				publicData.them &&
				publicData.them.length &&
				publicData.them[0].public_keys &&
				publicData.them[0].public_keys.primary &&
				publicData.them[0].public_keys.primary.bundle) {
				var user = publicData.them[0];
				kbpgp.KeyManager.import_from_armored_pgp(
					{armored: user.public_keys.primary.bundle},
					createKeyManagerCallback(resp, blob, signature, user)
				);
			}
		});
	};

	var lookupUrl = formatString(pkey_url, blob.email_or_username);
	https.get(lookupUrl, lookupCallback);
}

router.map(function() {
	this.get(/^\/api\/hello_world\/?$/).bind(function(req, resp) {
		resp.send(200, { 'Content-Type': 'application/json' }, { message: "Hello World" });
	});
	this.post(/^\/api\/kb_cert_verify\/?$/).bind(kbCertVerify);
});

http.createServer(function(req, res) {
	var body = '';

	// Append the chunk to body
	req.addListener('data', function (chunk) {
		body += chunk;
	});

    req.addListener('end', function() {
		router.handle(req, body, function (route) {
			if (route.status === 404) {
				// Log the 404
				console.log('Router did not match request for: ' + req.url);

				//fileServer.serve(req, res, makeResponseCallback(req, res));
				fileServer.serve(req, res, function (err, result) {
					// If the file wasn't found
					if (err && (err.status === 404)) {
						res.writeHead(404);
						res.end('File not found.');
					}
				});
				return;
			}

			res.writeHead(route.status, route.headers);
			res.end(route.body);
		});
    });
}).listen(port);
