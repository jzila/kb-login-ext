chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
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
        key_b64: null,
        key_manager: null
    },
    public_key: ''
};

function renderStatus(statusCode, statusText) {
	if (!statusText) {
		if (keys.private_key.key_b64) {
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
		$('#submit').prop('disabled', false);
		$('#button-spinner').attr("class", "hidden");
	} else {
		$('#submit').prop('disabled', true);
		$('#button-spinner').attr("class", "");
	}
    $('#status').text(statusText);
	console.log("status: " + statusText);
}

function formatString(format) {
    var args = Array.prototype.slice.call(arguments, 1);
    return format.replace(/{(\d+)}/g, function(match, number) { 
        return typeof args[number] != 'undefined' ? args[number] : match;
    });
}

function decryptKey(pkey_passwd) {
    var key_b64 = keys.private_key.key_b64;
    kbpgp.KeyManager.import_from_p3skb({raw: key_b64}, function(err, km) {
        if (km.is_p3skb_locked()) {
            km.unlock_p3skb({passphrase: pkey_passwd}, function(err) {
                if (!err) {
                    keys.private_key.key_manager = km;
                    renderStatus(-1);
					chrome.tabs.executeScript({file: "content_signing_data.js"});
                }
            });
        } else {
            renderStatus(1, "Private key not locked");
        }
    });
}

function handleKbLoginData(data) {
	if (data) {
		try {
			blob = JSON.parse(data);
			if (validateBlob(blob)) {
				blob.email_or_username = kb_id;
				signAndPostBlob(blob.kb_post_url, JSON.stringify(blob));
			} else {
				renderStatus(1, "Server signing blob has incorrect parameters.")
			}
		} catch (SyntaxError) {
			renderStatus(1, "Unable to parse JSON from server");
		}
	}
}

function validateBlob(blob) {
	return blob.siteId && blob.kb_post_url && blob.nonce && blob.nonce.length >= 32;
}

function signAndPostBlob(url, blobString) {
	// TODO sign blob here
	kbpgp.box({
		msg: blobString,
		sign_with: keys.private_key.key_manager
	}, function(err, result_string) {
		if (!err) {
			$.ajax({
				url: url,
				type: "POST",
				data: {
					blob: blobString,
					signature: result_string
				},
				success: function(data) {
					renderStatus(0, "Logged in as " + data.user.full_name);
				},
				error: function() {
					renderStatus(1, "Unable to verify identity");
				}
			});
		}
	});
}

function resetForm() {
	keys.private_key = {
		key_b64: null,
		key_manager: null
	};
	kb_id = '';
	renderStatus(1);
}

$(document).ready(function() {
	renderStatus(1);
    $('#submit').click(function() {
		$(this).focus();
        renderStatus(-1);
        kb_id = $('#kb-id').val();
        var pkey_passwd = $('#pkey-password').val();
		$('#pkey-password').val('');

        // TODO sanitize and validate text for both fields
        
        $.getJSON(formatString(salt_url, kb_id), function(salt_data) {
            var salt = new triplesec.Buffer(salt_data["salt"], 'hex');
            var login_session = new triplesec.Buffer(salt_data["login_session"], 'base64');
            var key = new triplesec.Buffer(pkey_passwd, 'utf8');
            var pwh_derived_key_bytes = 32;
            var encryptor = new triplesec.Encryptor({
                key: key,
                version: 3
            });
			encryptor.resalt({
                salt: salt,
                extra_keymaterial: pwh_derived_key_bytes
            }, function(err, km) {
                if (!err) {
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
                        success: function(data) {
                            if (data.status.name == "OK") {
                                keys.private_key.key_b64 = data.me.private_keys.primary.bundle;
                                decryptKey(pkey_passwd);
                            } else if (data.status.name == "BAD_LOGIN_PASSWORD") {
                                renderStatus(1, "Invalid login or password");
                            } else {
								renderStatus(1, "Unknown error occurred with login");
							}
                        },
                        error: function(err) {
                            renderStatus(1, "Unable to login to " + login_url);
                        }
                    });
                } else {
                    renderStatus(1, "Error occurred while encrypting password");
                }
            });
        }).fail(function(err) {
            renderStatus(1, "Failed to get salt");
        });
    });
	$('#kb-id').on('input', function() {
		resetForm();
	}).focus();
});
