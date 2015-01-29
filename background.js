chrome.runtime.onInstalled.addListener(function() {
	chrome.declarativeContent.onPageChanged.removeRules(undefined, function() {
		chrome.declarativeContent.onPageChanged.addRules([{
			conditions: [
				// When a page contains the matched element
				new chrome.declarativeContent.PageStateMatcher({
					css: ["#kb-login-blob"]
				})
			],
			// ... show the page action.
			actions: [ new chrome.declarativeContent.ShowPageAction() ]
		}]);
	});
});
