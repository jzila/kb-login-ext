var exports = module.exports = {};

exports.formatString = function (format) {
	var args = Array.prototype.slice.call(arguments, 1);
	return format.replace(/{(\d+)}/g, function (match, number) {
		return typeof args[number] != 'undefined' ? args[number] : match;
	});
};

exports.makeSendResponse = function (resp) {
	return function (code, stringOrObj) {
		resp.status(code).send(stringOrObj);
	}
};
