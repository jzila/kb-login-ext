var nodeStatic = require("node-static"),
	http = require("http"),
	journey = require("journey"),
	kblib = require("./api/kblib.js"),
	util = require("./lib/util.js"),
	constants = require("./constants.js");

var port = process.env.PORT;

var router = new journey.Router();
var fileServer = new nodeStatic.Server("./static");

router.map(function () {
	this.get(/^\/api\/get_blob\/?$/).bind(function (req, resp) {
		var cb = util.makeSendResponse(resp);
		var host = req.headers.referer;
		if (host.lastIndexOf('/') == host.length - 1) {
			host = host.slice(0, host.length - 1);
		}
		kblib.getBlob("kb-login-demo", host + constants.API_KB_VERIFY, cb);
	});
	this.post(/^\/api\/kb_cert_verify\/?$/).bind(function (req, resp, data) {
		var cb = util.makeSendResponse(resp);
		kblib.kbCertVerify(data, cb);
	});
});

http.createServer(function (req, res) {
	var body = '';

	// Append the chunk to body
	req.addListener('data', function (chunk) {
		body += chunk;
	});

	req.addListener('end', function () {
		router.handle(req, body, function (route) {
			if (route.status === 404) {
				// Log the 404
				console.log('Router did not match request for: ' + req.url);

				//fileServer.serve(req, res, makeResponseCallback(req, res));
				fileServer.serve(req, res, function (err, result) {
					// If the file wasn't found
					if (err && (err.status === 404)) {
						res.writeHead(404);
						res.end('File not found.');
					}
				});
				return;
			}

			res.writeHead(route.status, route.headers);
			res.end(route.body);
		});
	});
}).listen(port);
