chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
	if (request.kb_blob) {
		handleKbLoginData(request.kb_blob);
		sendResponse({ack: true});
	} else if (request.user) {
        var user_name = request.user.full_name || request.user.kb_username;
        renderStatus(0, "Logged in as " + user_name);
    } else if (request.error) {
        resetForm(request.error);
    }
});

var login_url = "https://keybase.io/_/api/1.0/login.json";
var salt_url = "https://keybase.io/_/api/1.0/getsalt.json?email_or_username={0}";
var crypt = require('crypto');
var kb_id = '';
var kb_login_regex = /^[a-zA-Z0-9_@.+-]+$/;
var keys = {
	private_key: {
		key_encrypted: null,
		key_manager: null,
		key_fingerprint: null,
	}
};

var KeyManager = kbpgp.KeyManager;

KeyManager.prototype.has_private = function() {
	return this.has_pgp_private() || this.has_p3skb_private();
};

KeyManager.prototype.is_locked = function() {
	return this.is_pgp_locked() || this.is_p3skb_locked();
};

KeyManager.prototype.unlock = function(params, cb) {
	if (this.is_pgp_locked()) {
		return this.unlock_pgp(params, cb);
	} else if (this.is_p3skb_locked()) {
		return this.unlock_p3skb(params, cb);
	} else {
		cb(true);
	}
};


function renderStatus(statusCode, statusText) {
	if (!statusText) {
		if (keyExists()) {
			if (keyEncrypted()) {
				statusText = "Private key encrypted";
			} else {
				statusText = "Private key loaded";
			}
		} else {
			statusText = "No key";
		}
	}
	if (statusCode === 0) {
		$('#kb-id').addClass('signed-in');
	} else {
		$('#kb-id').removeClass('signed-in');
	}
	if (statusCode >= 0) {
		if (keyExists()) {
			if (keyEncrypted()) {
				$("#pkey-container").addClass("hidden");
				$("#pkey-password").removeClass("hidden");
				$("#submit").removeClass("hidden");
			} else {
				$("#pkey-container").addClass("hidden");
				$("#pkey-password").addClass("hidden");
				$("#submit").addClass("hidden");
			}
		} else {
			$("#pkey-container").removeClass("hidden");
			$("#pkey-password").addClass("hidden");
			$("#submit").removeClass("hidden");
		}
		$('#submit').prop('disabled', false);
		$('#button-spinner').attr("class", "hidden");
		focusFirstEmpty();
	} else {
		$('#submit').prop('disabled', true);
		$('#button-spinner').attr("class", "");
	}
	$('#status').text(statusText);
	console.log("status: " + statusText);
}

function formatString(format) {
	var args = Array.prototype.slice.call(arguments, 1);
	return format.replace(/{(\d+)}/g, function (match, number) {
		return typeof args[number] != 'undefined' ? args[number] : match;
	});
}

function handleKeyUnlock(km, pkey_passwd) {
	if (!km.has_private()) {
		renderStatus(1, "No private key supplied");
	} else if (km.is_locked()) {
		km.unlock({passphrase: pkey_passwd}, function (err) {
			if (!err) {
				keys.private_key.key_manager = km;
				renderStatus(-1, "Requesting message to sign...");
				chrome.tabs.executeScript({file: "content_signing_data.js"});
			} else {
				renderStatus(1, "Error decrypting private key");
			}
		});
	} else {
		renderStatus(1, "Private key not encrypted");
	}
}

function importKey(cb) {
	var key_encrypted = keys.private_key.key_encrypted;
	KeyManager.import_from_p3skb({armored: key_encrypted}, function (err, km) {
		if (!err) {
			keys.private_key.key_manager = km;
			if (cb) {
				cb();
			}
		} else {
			kbpgp.KeyManager.import_from_armored_pgp({armored: key_encrypted}, function(err, kmpgp) {
				if (!err) {
					keys.private_key.key_manager = kmpgp;
					if (cb) {
						cb();
					}
				} else {
					renderStatus(1, "Error importing private key");
				}
			});
		}
	});
}

function decryptKey(pkey_passwd) {
	renderStatus(-1, "Decrypting private key...");
	var key_encrypted = keys.private_key.key_encrypted;
	KeyManager.import_from_p3skb({armored: key_encrypted}, function (err, km) {
		if (!err) {
			handleKeyUnlock(km, pkey_passwd);
		} else {
			kbpgp.KeyManager.import_from_armored_pgp({armored: key_encrypted}, function(err, km) {
				if (!err) {
					handleKeyUnlock(km, pkey_passwd);
				} else {
					renderStatus(1, "Error importing private key");
				}
			});
		}
	});
}

function generateNonce() {
	var arr = new Uint32Array(4);
	crypto.getRandomValues(arr);
	return $.makeArray(arr).reduce(function(acc, cur) {
		return acc + cur.toString(16);
	}, "");
}

function handleKbLoginData(data) {
	renderStatus(-1, "Signing server data...");
	var blob;
	if ((blob = parseBlob(data))) {
		blob.email_or_username = kb_id;
		blob.fingerprint = keys.private_key.key_manager.get_pgp_fingerprint().toString('hex');
		blob.kb_login_ext_nonce = generateNonce();
		blob.kb_login_ext_annotation = "Auto-signed by kb_login_ext (https://github.com/jzila/kb-login-ext/)";
		signAndSendBlob(JSON.stringify(blob));
	}
}

function parseBlob(data) {
	if (!data) {
		renderStatus(1, "No signing data received from server");
	} else if (data.length > 300) {
		renderStatus(1, "Server blob too large");
	}
	try {
		var blob = JSON.parse(data);
		if (blob.siteId && blob.token && blob.token.length >= 85) {
			return blob;
		} else {
			renderStatus(1, "Unable to validate server blob");
		}
	} catch (SyntaxError) {
		renderStatus(1, "Unable to parse JSON from server");
	}
	return null;
}

function signAndSendBlob(blobString) {
	kbpgp.box({
		msg: blobString,
		sign_with: keys.private_key.key_manager
	}, function (err, result_string) {
		if (!err) {
            sendSignedBlobMessage({
                blob: blobString,
                signature: result_string
            });
		} else {
			renderStatus(1, "Error signing blob");
		}
	});
}

function sendSignedBlobMessage(data) {
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
		chrome.tabs.sendMessage(tabs[0].id, data, function(response) {
            if (response.message) {
                console.log(response.message);
            }
		});
	});
}

function resetForm(message) {
	$('#kb-id').val('');
	$('#kb-password').val('');
	$('#pkey-password').val('');
	$('#pkey-local').val('');
	resetData(message);
}

function resetData(message) {
	keys.private_key = {
		key_b64: null,
		key_manager: null
	};
	kb_id = '';
	clearKeysFromStorage(function() {
		renderStatus(1, message);
	});
}

function clearKeysFromStorage(cb) {
	chrome.storage.local.remove(["kb-private-key", "kb-id"], cb);
}

function getKeyFromStorage() {
	chrome.storage.local.get(["kb-private-key", "kb-id"], function(objects) {
		if (objects["kb-private-key"]) {
			keys.private_key.key_encrypted = objects["kb-private-key"];
			importKey();
			kb_id = objects["kb-id"];
			$('#kb-id').val(kb_id);
		}
		renderStatus(1);
	});
}

function saveKeyToStorage() {
	chrome.storage.local.set({
		"kb-private-key": keys.private_key.key_encrypted,
		"kb-id": kb_id
	}, function() {
		renderStatus(1);
	});
}

function handleKeySubmit() {
	var kb_passwd_field = $('#kb-password');
	var private_key_field = $('#pkey-local');
	var kb_id_field = $('#kb-id');
	kb_id = kb_id_field.val();

	if (private_key_field.val()) {
		keys.private_key.key_encrypted = private_key_field.val();
		importKey(saveKeyToStorage);
	} else if (!kb_id) {
		renderStatus(1, "Keybase ID or private key required");
	} else if (!kb_id.match(kb_login_regex)) {
		renderStatus(1, "Invalid Keybase ID");
	} else if (kb_passwd_field.val()) {
		processKbLogin(kb_passwd_field.val());
		kb_passwd_field.val("");
	}
}

function processKbLogin(kb_passwd) {
	renderStatus(-1, "Requesting salt from Keybase...");

	// TODO Issue #1 sanitize and validate text for both fields

	$.getJSON(formatString(salt_url, kb_id), function (salt_data) {
		if (salt_data && salt_data.status && salt_data.status.code === 0) {
			renderStatus(-1, "Salting and encrypting passphrase...");
			var salt = new triplesec.Buffer(salt_data["salt"], 'hex');
			var login_session = new triplesec.Buffer(salt_data["login_session"], 'base64');
			var key = new triplesec.Buffer(kb_passwd, 'utf8');
			var pwh_derived_key_bytes = 32;
			var encryptor = new triplesec.Encryptor({
				key: key,
				version: 3
			});
			encryptor.resalt({
				salt: salt,
				extra_keymaterial: pwh_derived_key_bytes
			}, function (err, km) {
				if (!err) {
					renderStatus(-1, "Hashing encrypted passphrase...");
					var pwh = km.extra.slice(0, pwh_derived_key_bytes);
					var hmac = crypt.createHmac('sha512', pwh).update(login_session);
					var digest = hmac.digest('hex');

					$.ajax({
						url: login_url,
						type: "POST",
						data: {
							email_or_username: kb_id,
							hmac_pwh: digest,
							login_session: salt_data["login_session"]
						},
						success: function (data) {
							if (data.status.name == "OK") {
								if (data.me &&
									data.me.private_keys &&
									data.me.private_keys.primary &&
									data.me.private_keys.primary.bundle) {
									keys.private_key.key_encrypted = data.me.private_keys.primary.bundle;
									importKey(saveKeyToStorage);
								} else {
									renderStatus(1, "No private key found in that Keybase");
								}
							} else if (data.status.name == "BAD_LOGIN_PASSWORD") {
								renderStatus(1, "Invalid login or password");
							} else {
								renderStatus(1, "Unknown error occurred with login");
							}
						},
						error: function (err) {
							renderStatus(1, "Unable to login to " + login_url);
						}
					});
				} else {
					renderStatus(1, "Error occurred while encrypting password");
				}
			});
		} else {
			renderStatus(1, "Failed to get salt; invalid username");
		}
	}).fail(function (err) {
		renderStatus(1, "Failed to get salt; invalid username");
	});
}

function keyExists() {
	return !!keys.private_key.key_encrypted;
}

function keyEncrypted() {
	return keyExists() && keys.private_key.key_manager && keys.private_key.key_manager.is_locked();
}

function focusFirstEmpty() {
	if (keyExists()) {
		$("#pkey-password").focus();
	} else if (kb_id) {
		$("#kb-password").focus();
	} else {
		$("#kb-id").focus();
	}
}

$(document).ready(function() {
	getKeyFromStorage();
	$('#submit').click(function() {
		$(this).focus();
		renderStatus(-1);
		if (keyExists()) {
			var pkey_password_field = $("#pkey-password");
			if (pkey_password_field.val()) {
				decryptKey(pkey_password_field.val());
				pkey_password_field.val("");
			} else {
				resetForm();
			}
		} else {
			handleKeySubmit();
		}
	});
	$('#use-private').click(function() {
		resetForm();
		var p = $(this).parent();
		if (p.hasClass("local")) {
			p.removeClass("local").addClass("keybase");
		} else {
			p.addClass("local").removeClass("keybase");
		}
	});
	$('#kb-id').on('input', function() {
		resetData();
	});
	focusFirstEmpty();
});
