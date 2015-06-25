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

var F = kbpgp.const.openpgp;
var crypt = require('crypto');
var keys = {
    key_pair: {
        fingerprint: null,
        key_manager: null,
        signed_public_key: null,
        private_key: null
    }
};
var timeout = null;

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
    if (timeout) {
        clearTimeout(timeout);
        timeout = null;
    }
    if (!statusText) {
        if (keyExists()) {
            statusText = "Private key loaded";
        } else {
            statusText = "No key";
        }
    }
    if (statusCode === 0) {
        $('#status').addClass('signed-in');
    } else {
        $('#status').removeClass('signed-in');
    }
    if (statusCode >= 0) {
        if (keyExists()) {
            $("#pkey-container").addClass('hidden');
            $("#reset").removeClass("hidden");
            $("#submit").addClass("hidden");
        } else {
            $("#pkey-container").removeClass('hidden');
            $("#reset").addClass("hidden");
            $("#submit").removeClass("hidden");
        }
        $('#submit').prop('disabled', false);
        $('#button-spinner').attr("class", "hidden");
        focusFirstEmpty();
    } else {
        $("#pkey-container").addClass('hidden');
        $("#reset").addClass("hidden");
        $('#submit').removeClass("hidden").prop('disabled', true);
        $('#button-spinner').attr("class", "");
        statusText += "...";
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
                generateKeyPair(km);
            } else {
                renderStatus(1, "Error decrypting private key");
            }
        });
    } else {
        renderStatus(1, "Private key not encrypted");
    }
}

function requestBlobToSign() {
    renderStatus(-1, "Requesting message to sign");
    chrome.tabs.executeScript({file: "content_signing_data.js"});
}

function importKey(cb) {
    renderStatus(-1, "Importing key");
    KeyManager.import_from_armored_pgp({armored: keys.key_pair.private_key}, function(err, km) {
        if (!err) {
            keys.key_pair.key_manager = km;
            if (cb) {
                cb();
            }
        } else {
            resetData("Session key expired");
        }
    });
}

function decryptKey(key_encrypted, pkey_passwd) {
    renderStatus(-1, "Decrypting private key");
    KeyManager.import_from_armored_pgp({armored: key_encrypted}, function(err, km) {
        if (!err) {
            handleKeyUnlock(km, pkey_passwd);
        } else {
            renderStatus(1, "Error decrypting private key");
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
    renderStatus(-1, "Signing server data");
    var blob;
    if ((blob = parseBlob(data))) {
        blob.fingerprint = keys.key_pair.fingerprint;
        blob.kb_login_ext_nonce = generateNonce();
        blob.kb_login_ext_annotation = "Auto-signed by kb_login_ext (https://github.com/jzila/kb-login-ext/)";
        blob.signed_public_key = keys.key_pair.signed_public_key;
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
        sign_with: keys.key_pair.key_manager
    }, function (err, result_string) {
        if (!err) {
            renderStatus(-1, "Sending signature to website");
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
                renderStatus(-1, "Validating signature");
                console.log(response.message);
                timeout = setTimeout(function() {
                    renderStatus(1, "Timed out while validating signature");
                }, 10000);
            }
        });
    });
}

function resetForm(message) {
    $('#pkey-password').val('');
    $('#pkey-local').val('');
    resetData(message);
}

function resetData(message) {
    keys = {
        key_pair: {
            key_manager: null,
            signed_public_key: null,
            fingerprint: null,
            private_key: null,
        }
    };
    clearKeysFromStorage(function() {
        renderStatus(1, message);
    });
}

function clearKeysFromStorage(cb) {
    chrome.storage.local.clear(cb);
}

function getKeyFromStorage() {
    chrome.storage.local.get(["private-key", "signed-public-key", "key-fingerprint"], function(objects) {
        if (objects["private-key"]) {
            keys.key_pair.private_key = objects["private-key"];
            keys.key_pair.signed_public_key = objects["signed-public-key"];
            keys.key_pair.fingerprint = objects["key-fingerprint"];
            importKey(requestBlobToSign);
        } else {
            renderStatus(1);
        }
    });
}

function saveKeyToStorage() {
    chrome.storage.local.set({
        "private-key": keys.key_pair.private_key,
        "signed-public-key": keys.key_pair.signed_public_key,
        "key-fingerprint": keys.key_pair.fingerprint
    }, function() {
        renderStatus(1);
    });
}

function generateKeyPair(user_km) {
    renderStatus(-1, "Retrieving PGP fingerprint");
    if (user_km && user_km.get_pgp_fingerprint()) {
        keys.key_pair.fingerprint = user_km.get_pgp_fingerprint().toString('hex');
    } else {
        return renderStatus(1, "Could not retrieve key fingerprint");
    }
    var opts = {
        userid: "Keybase Login Extension",
        ecc: true,
        primary: {
            flags: F.certify_keys,
            nbits: 384,
            expire_in: 60 * 15
        },
        subkeys: [
            {
                flags : F.sign_data | F.auth,
                nbits : 256,
                expire_in: 60 * 15
            }
        ]
    };
    renderStatus(-1, "Generating session key pair");
    KeyManager.generate(opts, function(err, km) {
        if (!err) {
            renderStatus(-1, "Self-signing key pair");
            km.sign({}, function(err) {
                if (!err) {
                    keys.key_pair.key_manager = km;
                    renderStatus(-1, "Exporting private key");
                    km.export_pgp_private({}, function(err, pgp_private) {
                        if (!err) {
                            keys.key_pair.private_key = pgp_private;
                            renderStatus(-1, "Exporting public key");
                            km.export_pgp_public({}, function(err, pgp_public) {
                                if (!err && user_km && !user_km.is_locked()) {
                                    renderStatus(-1, "Signing public key with user key");
                                    kbpgp.box({
                                        msg: pgp_public,
                                        sign_with: user_km
                                    }, function(err, result_string) {
                                        if (!err) {
                                            keys.key_pair.signed_public_key = result_string;
                                            saveKeyToStorage();
                                            requestBlobToSign();
                                        } else {
                                            renderStatus(1, "Unable to sign key pair");
                                        }
                                    });
                                } else {
                                    renderStatus(1, "Unable to export public key");
                                }
                            });
                        } else {
                            renderStatus(1, "Unable to export private key. Error: " + err);
                        }
                    });
                } else {
                    renderStatus(1, "Unable to self-sign key. Error: " + err);
                }
            });
        } else {
            renderStatus(1, "Unable to generate key pair");
        }
    });
}

function handleKeySubmit() {
    $("#submit").focus();
    renderStatus(-1);
    var private_key_field = $('#pkey-local');
    var pkey_password_field = $("#pkey-password");
    if (private_key_field.val() && pkey_password_field.val()) {
        decryptKey(private_key_field.val(), pkey_password_field.val());
        pkey_password_field.val("");
    } else {
        resetForm();
        renderStatus(1, "Private key and passphrase required");
    }
}

function keyExists() {
    return !!keys.key_pair.key_manager;
}

function focusFirstEmpty() {
    if (!keyExists()) {
        $("#pkey-local").focus();
    }
}

$(document).ready(function() {
    getKeyFromStorage();
    $('#submit').click(handleKeySubmit);
    $('#reset').click(function() { resetForm(); });
    $('#pkey-local').on('input', function() { resetData(); });
    focusFirstEmpty();
});
