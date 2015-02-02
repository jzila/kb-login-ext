var socket, user;
function createKbElements(blob) {
	var input_string = "<input type=\"text\" style=\"width: 1px !important; height: 1px !important; position:absolute !important; top:-100px !important; left: -100px !important;\" />";
	$(input_string).attr("id", "kb-login-blob").prependTo($("body")).val(JSON.stringify(blob));
	$(input_string).attr("id", "kb-user-blob").prependTo($("body"));
}

function userChangeHandler() {
	var val;

	if (Object.getPrototypeOf(this) === HTMLInputElement.prototype && (val = $(this).val())) {
		user = JSON.parse(val);
		$("#name").text(user.full_name);
		$("#name-container").removeClass("hidden");
		$("#message,#submit").prop("disabled", false);
	} else {
		$("#name").text("");
		$("#name-container").addClass("hidden");
		$("#message,#submit").prop("disabled", true);
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

	userChangeHandler();
	$.ajax({
		url: "/api/get_blob/",
		type: "GET",
		success: function (blob) {
			createKbElements(blob);

			$("#kb-user-blob").change(userChangeHandler);
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
