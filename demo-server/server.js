var http = require("http"),
	path = require("path"),
	express = require("express"),
	bodyParser = require('body-parser'),
	multer = require('multer'),
	async = require('asyncawait/async'),
	await = require('asyncawait/await'),
	Promise = require('bluebird'),
	kblib = require("./api/kblib.js"),
	util = require("./lib/util.js"),
	constants = require("./constants.js");
var redis = Promise.promisifyAll(require('node-redis'));

var limitIncr = 1,
	maxRateLimit = 3,
	rateLimitIncrInterval = 2000;

var app = express();
var port = process.env.PORT || 8084;

//
// Redis setup for sessions and chat pubsub
//
var redisHost = process.env.REDIS_HOST || 'localhost';
var redisClient = redis.createClient(6379, redisHost);
var redisSubscriber = redis.createClient(6379, redisHost);
redisSubscriber.on("connect", function() {
	console.log("Redis client ready. Subscribing to " + chatChannel);
	redisSubscriber.subscribe(chatChannel);
});
var redisPrefix = "kb-login-demo:";
var sessionPrefix = redisPrefix + "sessions:";

var sessions = {};
var setSessionUser = function(token, user) {
	var b64 = (new Buffer(JSON.stringify(user))).toString('base64');
	redisClient.set(sessionPrefix + token, b64);
};
var getSessionUser = async.result(function(token) {
	var userBase64 = await(redisClient.getAsync(sessionPrefix + token));
	if (userBase64) {
		var buf = new Buffer(userBase64.toString(), 'base64');
		var buf_utf8 = buf.toString('utf8');
		return JSON.parse(buf_utf8);
	}
	return {};
});

var httpServer = http.Server(app);
var io = require('socket.io')(httpServer);

var chatChannel = redisPrefix + "chat-channel";
redisSubscriber.on("message", function(channel, message) {
	if (channel === chatChannel) {
		var buf = new Buffer(message.toString(), 'base64');
		var buf_json = buf.toString('utf8');
		var obj = JSON.parse(buf_json);
		io.emit("chat_message", obj);
	}
});


//
// Routes
//
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(multer());

app.use(express.static(__dirname + '/static'));

app.get(/^\/api\/get_blob\/?$/, function (req, resp) {
	var protocol = req.headers.referer.slice(0, req.headers.referer.indexOf("://"));

	kblib.getBlob(
		constants.SITE_ID,
		util.makeSendResponse(resp, function(blob) { setSessionUser(blob.token, {}); })
	);
});

app.post(/^\/api\/kb_cert_verify\/?$/, async(function (req, resp) {
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
}));


//
// Rate limiting
//
var limiter = {};

var initRateLimiter = function(id) {
	limiter[id] = maxRateLimit;
};

var checkRateLimit = function(id, errHandler) {
	var limit = limiter[id];
	if (limit == null || limit <= 0) {
		errHandler("You are doing that too much.");
		return false;
	} else {
		limiter[id]--;
	}
	return true;
};

var incrRateLimit = function() {
	var sockets = Object.keys(io.sockets.connected);
	for (var i=0; i<sockets.length; i++) {
		var socket = sockets[i];
		if (limiter[socket] != null && limiter[socket] < maxRateLimit) {
			limiter[socket] += limitIncr;
		}
	}
};

setInterval(incrRateLimit, rateLimitIncrInterval);


//
// Connection logging
//
var serverId = Math.floor(Math.random() * (0xffffffffffff - 0x100000000000) + 0x100000000000).toString(16);
var serverPrefix = redisPrefix + "servers:";

var clearServerFromRedis = async(function(id) {
	await(redisClient.delAsync(serverPrefix + id));
});

var incrementServerConnections = async(function(id) {
	await(redisClient.incrAsync(serverPrefix + id));
	connectionLog('User++');
});

var decrementServerConnections = async(function(id) {
	await(redisClient.decrAsync(serverPrefix + id));
	connectionLog('User--');
});

var connectionLog = async(function(prefix) {
	var feConnections = Object.keys(io.sockets.connected).length;
	var serverIds = await(redisClient.keysAsync(serverPrefix + "*"));
	var serverCounts = await(serverIds.map(function(serverId) {
		return function(cb) {
			redisClient.get(serverId, cb);
		};
	}));
	var totalCount = serverCounts.reduce(function(aInt, bStr) { return aInt + parseInt(bStr, 10); }, 0);
	console.log(prefix + ": server_connected: " + feConnections + ", total_connected: " + totalCount);
});


//
// Chat handling
//
io.on('connection', function(socket){
	incrementServerConnections(serverId);
	initRateLimiter(socket.id);
	var errHandler = function(err) {
		socket.emit("chat_error", err);
	};
	socket.on('disconnect', function(){
		decrementServerConnections(serverId);
	});
	socket.on("chat_message", async(function(obj) {
		if (checkRateLimit(socket.id, errHandler)) {
			var user;
			if (!obj.token || !(user = getSessionUser(obj.token))) {
				errHandler("Unrecognized user");
			} else {
				var msg = obj.message;
				if (msg.length > 1024) {
					msg = msg.substr(0, 1010) + "...[truncated]";
				}
				if (msg.trim().length > 0) {
					var obj = {user: user.kb_username, message: msg};
					var obj_base64 = new Buffer(JSON.stringify(obj)).toString('base64');
					redisClient.publish(chatChannel, obj_base64);
				}
			}
		}
	}));
});

httpServer.listen(port, function() {
	console.log("listening on " + port);
});

process.on('SIGINT', async(function() {
	console.log("shutting down server with ID: " + serverId);
	await(clearServerFromRedis(serverId));
	process.exit();
}));
