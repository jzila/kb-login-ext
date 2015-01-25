var pkey_url = "https://keybase.io/_/api/1.0/user/lookup.json?usernames={0}&fields=basics,profile,public_keys";
var login_url = "https://keybase.io/_/api/1.0/login.json";
var salt_url = "https://keybase.io/_/api/1.0/getsalt.json?email_or_username={0}";
var crypt = require('crypto');
var keys = {
    private_key: {
        key_b64: null,
        key_manager: null,
    },
    public_key: ''
};

function renderStatus(statusText) {
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
    $('#status').text(statusText);
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
                    renderStatus();
                }
            });
        } else {
            renderStatus();
        }
    });
}

$(document).ready(function() {
    $('#submit').click(function() {
        $(this).prop('disabled', true);
        renderStatus();
        var kb_id = $('#kb-id').val();
        var pkey_passwd = $('#pkey-password').val();

        // $('#pkey-password').val('');
        // TODO sanitize and validate text for both fields 
        
        $.getJSON(formatString(salt_url, kb_id), function(salt_data) {
            var salt = new triplesec.Buffer(salt_data["salt"], 'hex');
            var login_session = new triplesec.Buffer(salt_data["login_session"], 'base64');
            var key = new triplesec.Buffer(pkey_passwd, 'utf8');
            var encryptor = new triplesec.Encryptor({
                key: key,
                version: 3
            });
            var pwh = '';
            var pwh_derived_key_bytes = 32;
            var pgp_derived_key_bytes = 12;
            encryptor.resalt({
                salt: salt,
                extra_keymaterial: pwh_derived_key_bytes + pgp_derived_key_bytes
            }, function(err, km) {
                if (!err) {
                    pwh = km.extra.slice(0, pwh_derived_key_bytes);

                    var hmac = crypt.createHmac('sha512', pwh);
                    hmac.update(login_session);
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
                                renderStatus();
                            } else {
                                renderStatus(data.status.name);
                            }
                        },
                        error: function(err) {
                            console.log(err);
                        },
                        complete: function() {
                            $('#submit').prop('disabled', false);
                        }
                    });

                    var url = formatString(pkey_url, kb_id);
                } else {
                    renderStatus("Error occurred while encrypting password");
                    $('#submit').prop('disabled', false);
                }
            });
        }).fail(function(err) {
            renderStatus("Failed to get salt");
            $('#submit').prop('disabled', false);
        });

    });
});
