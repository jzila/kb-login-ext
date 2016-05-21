var kb_blob = document.getElementById("kb-login-blob").value;
var signature_blob = document.getElementById("kb-signature-blob");
var user_blob = document.getElementById("kb-user-blob");

console.log("Sending message to extension with blob " + kb_blob);
chrome.runtime.sendMessage({
    kb_blob: kb_blob
}, function () {
    console.log("Received ack from extension");
    chrome.runtime.onMessage.addListener(
        function(request, sender, sendResponse) {
            if (request) {
                if (request.blob && request.signature) {
                    signature_blob.value = JSON.stringify(request);
                    signature_blob.dispatchEvent(new CustomEvent("change"));
                    sendResponse({message: "Received signed blob"});
                    user_blob.addEventListener("change", function () {
                        console.log("user blob changed");
                        chrome.runtime.sendMessage(JSON.parse(user_blob.value), function () {
                            console.log("User blob change received by extension");
                        });
                    });
                }
            }
        }
    );

});
