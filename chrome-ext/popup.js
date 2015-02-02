chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
	if (request.kb_blob) {
		handleKbLoginData(request.kb_blob);
		sendResponse({ack: true});
	}
});

var login_url = "https://keybase.io/_/api/1.0/login.json";
var salt_url = "https://keybase.io/_/api/1.0/getsalt.json?email_or_username={0}";
var crypt = require('crypto');
var kb_id = '';
var keys = {
	private_key: {
		key_encrypted: null,
		key_manager: null
	}
};

function renderStatus(statusCode, statusText) {
	if (!statusText) {
		if (keys.private_key.key_encrypted) {
			if (keys.private_key.key_manager) {
				statusText = "Private key loaded";
			} else {
				statusText = "Private key encrypted";
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
	if (data) {
		try {
			renderStatus(-1, "Signing server data...");
			var blob;
			if ((blob = parseBlob(data))) {
				blob.email_or_username = kb_id;
				blob.kb_login_ext_nonce = generateNonce();
				blob.kb_login_ext_annotation = "Auto-signed by kb_login_ext (https://github.com/jzila/kb-login-ext/)";
				signAndPostBlob(blob.kb_post_url, JSON.stringify(blob));
			} else {
				renderStatus(1, "Server signing blob is invalid.");
			}
		} catch (SyntaxError) {
			renderStatus(1, "Unable to parse JSON from server");
		}
	} else {
		renderStatus(1, "No signing data received from server");
	}
}

function parseBlob(data) {
	if (data.length > 300) {
		return null;
	}
	var blob = JSON.parse(data);
	if (blob.siteId && blob.kb_post_url && blob.token && blob.token.length >= 85) {
		return blob;
	} else {
		return null;
	}
}

function signAndPostBlob(url, blobString) {
	kbpgp.box({
		msg: blobString,
		sign_with: keys.private_key.key_manager
	}, function (err, result_string) {
		if (!err) {
			$.ajax({
				url: url,
				type: "POST",
				data: {
					blob: blobString,
					signature: result_string
				},
				success: function (data) {
					sendUserMessage(data.user);
					renderStatus(0, "Logged in as " + data.user.full_name);
				},
				error: function () {
					renderStatus(1, "Unable to verify identity");
				}
			});
		}
	});
}

function sendUserMessage(user) {
	chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
		chrome.tabs.sendMessage(tabs[0].id, user, function(response) {
			console.log(response.message);
		});
	});
}

function resetForm() {
	keys.private_key = {
		key_b64: null,
		key_manager: null
	};
	kb_id = '';
	clearKeysFromStorage(function() { renderStatus(1); });
}

function clearKeysFromStorage(cb) {
	chrome.storage.local.remove(["kb-private-key", "kb-id"], cb);
}

function getKeyFromStorage() {
	chrome.storage.local.get(["kb-private-key", "kb-id"], function(objects) {
		if (objects["kb-private-key"] && objects["kb-id"]) {
			keys.private_key.key_encrypted = objects["kb-private-key"];
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

	if (!kb_id_field.val()) {
		renderStatus(1, "Keybase ID required");
	} else {
		kb_id = kb_id_field.val();
		if (kb_passwd_field.val()) {
			processKbLogin(kb_passwd_field.val());
			kb_passwd_field.val("");
		} else if (private_key_field.val()) {
			keys.private_key.key_encrypted = private_key_field.val();
			saveKeyToStorage();
		}
	}
}

function processKbLogin(kb_passwd) {
	renderStatus(-1, "Requesting salt from Keybase...");

	// TODO Issue #1 sanitize and validate text for both fields

	$.getJSON(formatString(salt_url, kb_id), function (salt_data) {
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
								saveKeyToStorage();
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
	}).fail(function (err) {
		renderStatus(1, "Failed to get salt");
	});
}

function keyExists() {
	return !!keys.private_key.key_encrypted;
}

function keyEncrypted() {
	return keyExists() && !keys.private_key.key_manager;
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
			decryptKey(pkey_password_field.val());
			pkey_password_field.val("");
		} else {
			handleKeySubmit();
		}
	});
	$('#use-private').click(function() {
		if ($(this).hasClass("local")) {
			$(this).removeClass("local").addClass("keybase");
			$("#pkey-local").removeClass("hidden");
			$("#kb-password").addClass("hidden");
		} else {
			$(this).addClass("local").removeClass("keybase");
			$("#pkey-local").addClass("hidden");
			$("#kb-password").removeClass("hidden");
		}
	});
	$('#kb-id').on('input', function() {
		resetForm();
	});
	focusFirstEmpty();
});
