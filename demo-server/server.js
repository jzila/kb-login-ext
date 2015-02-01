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
var userTokens = {};
var setSessionUser = function(token, user) {
	if (user && user.kb_uid) {
		if (userTokens[user.kb_uid]) {
			var oldUserToken = userTokens[user.kb_uid];
			if (sessions[oldUserToken]) {
				delete sessions[oldUserToken];
			}
		}
		userTokens[user.kb_uid] = token;
	}
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
	var protocol = req.headers.referer.slice(0, req.headers.referer.indexOf("://"));
	var url = protocol + "://" + req.headers.host + constants.API_KB_VERIFY;

	kblib.getBlob(
		constants.SITE_ID,
		url,
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
	var errHandler = function(err) {
		socket.emit("chat_error", err);
	};
	socket.on('disconnect', function(){
		console.log('user disconnected');
	});
	socket.on("chat_message", function(obj) {
		if (!obj.token || !sessions[obj.token]) {
			errHandler("Unrecognized user");
		} else {
			var user = sessions[obj.token];
			io.emit("chat_message", {user: user.kb_username, message: obj.message});
		}
	});
});

httpServer.listen(port, function() {
	console.log("listening on " + port);
});

