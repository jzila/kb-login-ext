var http = require("http"),
	path = require("path"),
	express = require("express"),
	bodyParser = require('body-parser'),
	multer = require('multer'),
	async = require('asyncawait/async'),
	await = require('asyncawait/await'),
	Promise = require('bluebird'),
    sticky = require('sticky-session'),
	kblib = require("./api/kblib.js"),
	util = require("./lib/util.js"),
	constants = require("./constants.js");
var redis = Promise.promisifyAll(require('node-redis'));

var app = express();
var port = process.env.PORT || 8084;

// Redis session handling
var redisPrefix = "kb-login-demo:";
var sessionPrefix = redisPrefix + "sessions:";
var chatChannel = redisPrefix + "chat-channel";
var redisHost = process.env.REDIS_HOST || 'localhost';
var redisClient = redis.createClient(6379, redisHost);
var redisSubscriber = redis.createClient(6379, redisHost);
redisSubscriber.on("connect", function() {
	console.log("Redis client ready. Subscribing to " + chatChannel);
	redisSubscriber.subscribe(chatChannel);
});

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

sticky(function() {
    var httpServer = http.Server(app);
    var io = require('socket.io')(httpServer);

    redisSubscriber.on("message", function(channel, message) {
        if (channel === chatChannel) {
            var buf = new Buffer(message.toString(), 'base64');
            var buf_json = buf.toString('utf8');
            var obj = JSON.parse(buf_json);
            io.emit("chat_message", obj);
        }
    });

    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(multer());

    app.use(express.static(__dirname + '/static'));

    app.get(/^\/api\/get_blob\/?$/, function (req, resp) {
        var protocol = req.headers.referer.slice(0, req.headers.referer.indexOf("://"));
        var url = protocol + "://" + req.headers.host + constants.API_KB_VERIFY;

        kblib.getBlob(
            constants.SITE_ID,
            url,
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

    io.on('connection', function(socket){
        console.log('a user connected');
        var errHandler = function(err) {
            socket.emit("chat_error", err);
        };
        socket.on('disconnect', function(){
            console.log('user disconnected');
        });
        socket.on("chat_message", async(function(obj) {
            var user;
            if (!obj.token || !(user = getSessionUser(obj.token))) {
                errHandler("Unrecognized user");
            } else {
                var msg = obj.message;
                if (msg.length > 1024) {
                    msg = msg.substr(0, 1010) + "...[truncated]";
                }
                var obj = {user: user.kb_username, message: msg};
                var obj_base64 = new Buffer(JSON.stringify(obj)).toString('base64');
                redisClient.publish(chatChannel, obj_base64);
            }
        }));
    });

    return httpServer;
}).listen(port, function() {
    console.log("listening on " + port);
});

