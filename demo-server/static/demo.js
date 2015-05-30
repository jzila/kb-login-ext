var socket, user;
function createKbElements(blob) {
	var input_string = "<input type=\"text\" style=\"width: 1px !important; height: 1px !important; position:absolute !important; top:-100px !important; left: -100px !important;\" />";
	$(input_string).attr("id", "kb-login-blob").prependTo($("body")).val(JSON.stringify(blob));
	$(input_string).attr("id", "kb-signature-blob").prependTo($("body"));
	$(input_string).attr("id", "kb-user-blob").prependTo($("body"));
}

function userUpdateHandler(u) {
	if (u) {
        user = u;
		$("#name").text(user.full_name || user.kb_username);
		$("#name-container").removeClass("hidden");
		$("#message,#submit").prop("disabled", false);
	} else {
		$("#name").text("");
		$("#name-container").addClass("hidden");
		$("#message,#submit").prop("disabled", true);
	}
}

function signatureChangeHandler(evt) {
	var val;

	if (Object.getPrototypeOf(this) === HTMLInputElement.prototype && (val = $(this).val())) {
		var data = JSON.parse(val);
        var user_blob = $('#kb-user-blob');
        $.ajax({
            url: "/api/kb_cert_verify/",
            type: "POST",
            data: data,
            success: function (data) {
                userUpdateHandler(data.user);
                user_blob.val(JSON.stringify({user: data.user}));
                user_blob[0].dispatchEvent(new CustomEvent("change"));
            },
            error: function () {
                user_blob.val(JSON.stringify({error: "Unable to verify identity"}));
                user_blob[0].dispatchEvent(new CustomEvent("change"));
            }
        });
	}
}

$(document).ready(function () {
	socket = io();

	socket.on("chat_message", function (obj) {
		var user = obj.user;
		var message = obj.message;
		$('#messages').append($('<li>').text(user + ": " + message));
		window.scrollTo(0, document.body.scrollHeight);
	});
	socket.on("chat_error", function (err) {
		$('#messages').append($("<li class=\"error\">").text(err));
		window.scrollTo(0, document.body.scrollHeight);
	});

	userUpdateHandler();
	$.ajax({
		url: "/api/get_blob/",
		type: "GET",
		success: function (blob) {
			createKbElements(blob);

			$("#kb-signature-blob").change(signatureChangeHandler);
		}
	});

	$("form").submit(function () {
		var msg = $("#message");
		socket.emit("chat_message", {
			message: msg.val(),
			token: user.token
		});
		msg.val("");
		return false;
	});
});
