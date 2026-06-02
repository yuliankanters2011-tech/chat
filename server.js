require('dotenv').config()
const express = require('express')
const app = express()

const path = require('path')
const fs = require('fs')

const html = path.join(__dirname, '/html');
app.use(express.static(html))

const port = process.argv[2] || 8090;
const http = require("http").Server(app);

const maxHttpBufferSizeInMb = parseInt(process.env.MAX_HTTP_BUFFER_SIZE_MB || '1');
const io = require("socket.io")(http, {
	maxHttpBufferSize: maxHttpBufferSizeInMb * 1024 * 1024,
});

let messageCache = [];
let cache_size = process.env.CACHE_SIZE ?? 0

// ====================
// BLOCKED WORDS SYSTEM
// ====================

let badWords = [];

function loadBadWords() {
	try {
		badWords = fs.readFileSync('/data/blocked-words.txt', 'utf8')
			.split('\n')
			.map(w => w.trim())
			.filter(Boolean);

		console.log(`Loaded ${badWords.length} blocked words.`);
	} catch (err) {
		console.error('Failed to load blocked words:', err.message);
		badWords = [];
	}
}

function filterMessage(text) {
	if (text === null || text === undefined) {
		return '';
	}

	if (typeof text !== 'string') {
		try {
			text = JSON.stringify(text);
		} catch (e) {
			text = String(text);
		}
	}

	let out = text;

	badWords.forEach(word => {
		const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
		const regex = new RegExp(escaped, 'gi');
		out = out.replace(regex, '*'.repeat(word.length));
	});

	return out;
}

loadBadWords();
setInterval(loadBadWords, 30000);

// ====================

http.listen(port, function(){
	console.log("Starting server on port %s", port);
});

const users = [];
let msg_id = 1;

io.sockets.on("connection", function(socket){
	console.log("New connection!");

	var nick = null;

	socket.on("login", function(data){

		data.nick = data.nick.trim();

		if(data.nick == ""){
			socket.emit("force-login", "Nick can't be empty.");
			nick = null;
			return;
		}

		if(users.indexOf(data.nick) != -1){
			socket.emit("force-login", "This nick is already in chat.");
			nick = null;
			return;
		}

		nick = data.nick;
		users.push(data.nick);

		console.log("User %s joined.", nick.replace(/(<([^>]+)>)/ig, ""));
		socket.join("main");

		io.to("main").emit("ue", {
			"nick": nick
		});

		socket.emit("start", {
			"users": users
		});

		console.log(`going to send cache to ${nick}`);

		socket.emit("previous-msg", {
			"msgs": messageCache
		});
	});

	socket.on("send-msg", function(data){

		if(nick == null){
			socket.emit("force-login", "You need to be logged in to send message.");
			return;
		}

		let messageText = '';

		if (typeof data === 'string') {
			messageText = data;
		}
		else if (typeof data?.m === 'string') {
			messageText = data.m;
		}
		else if (typeof data?.message === 'string') {
			messageText = data.message;
		}
		else {
			try {
				messageText = JSON.stringify(data);
			} catch (e) {
				messageText = String(data);
			}
		}

		console.log("RAW DATA:", JSON.stringify(data, null, 2));

const msg = {
	"f": nick,
	"m": data.m,
	"id": "msg_" + (msg_id++)
}
		messageCache.push(msg);

		if(messageCache.length > cache_size){
			messageCache.shift();
		}

		io.to("main").emit("new-msg", msg);

		console.log("User %s sent message.", nick.replace(/(<([^>]+)>)/ig, ""));
	});

	socket.on("typing", function(typing){

		if(nick != null){
			socket.broadcast.to("main").emit("typing", {
				status: typing,
				nick: nick
			});

			console.log("%s %s typing.", nick.replace(/(<([^>]+)>)/ig, ""), typing ? "is" : "is not");
		}
	});

	socket.on("disconnect", function(){

		console.log("Got disconnect!");

		if(nick != null){

			users.splice(users.indexOf(nick), 1);

			io.to("main").emit("ul", {
				"nick": nick
			});

			console.log("User %s left.", nick.replace(/(<([^>]+)>)/ig, ""));
			socket.leave("main");
			nick = null;
		}
	});
});
