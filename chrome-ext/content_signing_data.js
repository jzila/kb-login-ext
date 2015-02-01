var kb_blob = document.getElementById("kb-login-blob").value;

console.log("Sending message to extension with blob " + kb_blob);
chrome.runtime.sendMessage({
	kb_blob: kb_blob
}, function () {
	console.log("Received ack from extension");
	chrome.runtime.onMessage.addListener(
		function(request, sender, sendResponse) {
			if (request) {
				var user_blob = document.getElementById("kb-user-blob");
				user_blob.value = JSON.stringify(request);
				user_blob.dispatchEvent(new CustomEvent('change'));

				sendResponse({message: "Received user blob"});
			}
		}
	);
});
