var http = require("http"),
	path = require("path"),
	express = require('express')(),
	bodyParser = require('body-parser'),
	multer = require('multer'),
	kblib = require("./api/kblib.js"),
	util = require("./lib/util.js"),
	constants = require("./constants.js");

var port = process.env.PORT;

var httpServer = http.Server(express);
var io = require('socket.io')(httpServer);

express.use(bodyParser.json());
express.use(bodyParser.urlencoded({ extended: true }));
express.use(multer());

express.get(/^\/?$/, function(req, resp) {
	resp.sendFile(path.join(__dirname, "static/index.html"));
});

express.get(/^\/api\/get_blob\/?$/, function (req, resp) {
	var host = req.headers.referer;
	// Wipe the last slash if there is one
	if (host.lastIndexOf('/') == host.length - 1) {
		host = host.slice(0, host.length - 1);
	}
	kblib.getBlob(constants.SITE_ID, host + constants.API_KB_VERIFY, util.makeSendResponse(resp));
});

express.post(/^\/api\/kb_cert_verify\/?$/, function (req, resp) {
	kblib.kbCertVerify(req.body, util.makeSendResponse(resp));
});

io.on('connection', function(socket){
	console.log('a user connected');
	socket.on('disconnect', function(){
		console.log('user disconnected');
	});
});

httpServer.listen(port, function() {
	console.log("listening on " + port);
});

