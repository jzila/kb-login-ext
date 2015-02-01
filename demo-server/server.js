var http = require("http"),
	path = require("path"),
	app = require('express')(),
	bodyParser = require('body-parser'),
	multer = require('multer'),
	kblib = require("./api/kblib.js"),
	util = require("./lib/util.js"),
	constants = require("./constants.js");

var port = process.env.PORT;

// In-memory session handling
// TODO Issue #7 move out to something like Redis
var sessions = {};
var setSessionUser = function(token, user) {
	sessions[token] = user;
};
var getSessionUser = function(token) {
	return sessions[token];
};

var httpServer = http.Server(app);
var io = require('socket.io')(httpServer);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(multer());

app.get(/^\/?$/, function(req, resp) {
	resp.sendFile(path.join(__dirname, "static/index.html"));
});

app.get(/^\/api\/get_blob\/?$/, function (req, resp) {
	var host = req.headers.referer;
	// Wipe the last slash if there is one
	if (host.lastIndexOf('/') == host.length - 1) {
		host = host.slice(0, host.length - 1);
	}

	kblib.getBlob(
		constants.SITE_ID,
		host + constants.API_KB_VERIFY,
		util.makeSendResponse(resp, function(blob) { setSessionUser(blob.token, {}); })
	);
});

app.post(/^\/api\/kb_cert_verify\/?$/, function (req, resp) {
	var errResponseCb = util.makeSendResponse(resp);
	if (!req.body.blob || !req.body.signature) {
		console.log("Signature data not valid");
		return errResponseCb(400, "Invalid signature data");
	}
	var signature = req.body.signature;
	var blob = JSON.parse(req.body.blob);
	if (blob.token && getSessionUser(blob.token)) {
		kblib.kbCertVerify(
			blob,
			signature,
			util.makeSendResponse(resp, function(obj) { setSessionUser(obj.user.token, obj.user); })
		);
	} else {
		errResponseCb(400, "Unknown blob identifier");
	}
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

