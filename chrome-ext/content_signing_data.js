var kb_blob = document.getElementById("kb-login-blob").value;

console.log("Sending message to extension with blob " + kb_blob);
chrome.runtime.sendMessage({
	kb_blob: kb_blob
}, function () {
	console.log("Received ack from extension");
});
