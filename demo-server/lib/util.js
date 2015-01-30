var exports = module.exports = {};

exports.formatString = function (format) {
	var args = Array.prototype.slice.call(arguments, 1);
	return format.replace(/{(\d+)}/g, function (match, number) {
		return typeof args[number] != 'undefined' ? args[number] : match;
	});
};

exports.makeSendResponse = function (resp) {
	return function (code, stringOrObj) {
		if (code == 200) {
			var options = {};
			if (stringOrObj !== null && typeof stringOrObj === 'object') {
				options["Content-Type"] = "application/json";
			}
			resp.send(200, options, stringOrObj);
		} else {
			resp.send(code, stringOrObj);
		}
	}
};
