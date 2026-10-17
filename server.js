require('dotenv').config()
const express = require('express')
const app = express()

const path = require('path')
const fs = require('fs')
const crypto = require('crypto')

const html = path.join(__dirname, '/html');

// Injecteer fingerprint script in index.html zonder de originele bestanden te wijzigen
const fingerprintScript = `
<script>
(function() {
  function generateFingerprint() {
    var components = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || '',
      navigator.platform || ''
    ];
    var raw = components.join('|');
    var hash = 0;
    for (var i = 0; i < raw.length; i++) {
      hash = ((hash << 5) - hash) + raw.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }
  window.__deviceFingerprint = generateFingerprint();

  // Patch de socket.emit zodat fingerprint automatisch meegestuurd wordt bij login
  document.addEventListener('DOMContentLoaded', function() {
    var origEmit = null;
    var checkSocket = setInterval(function() {
      if (window.socket) {
        clearInterval(checkSocket);
        origEmit = window.socket.emit.bind(window.socket);
        window.socket.emit = function(event, data) {
          if (event === 'login' && data) {
            data.fingerprint = window.__deviceFingerprint;
          }
          return origEmit(event, data);
        };
      }
    }, 100);
  });
})();
</script>`;

app.get('/', function(req, res) {
  const indexPath = path.join(html, 'index.html');
  let content = fs.readFileSync(indexPath, 'utf8');
  // Injecteer vóór </head>
  content = content.replace('</head>', fingerprintScript + '</head>');
  res.send(content);
});

app.use(express.static(html));

const port = process.argv[2] || 8090;
const http = require("http").Server(app);

const maxHttpBufferSizeInMb = parseInt(process.env.MAX_HTTP_BUFFER_SIZE_MB || '1');
const io = require("socket.io")(http, {
	maxHttpBufferSize: maxHttpBufferSizeInMb * 1024 * 1024,
});

let messageCache = [];
let cache_size = process.env.CACHE_SIZE ?? 0;

// ====================
// ADMIN WACHTWOORD
// Lees uit /data/admin-password.txt — zelfde systeem als blocked-words.txt
// Staat NOOIT in de HTML of client-side JS
// ====================

let ADMIN_PASSWORD = 'changeme123';

function loadAdminPassword() {
	try {
		const pw = fs.readFileSync('/data/admin-password.txt', 'utf8').trim();
		if (pw.length > 0) {
			ADMIN_PASSWORD = pw;
			console.log('Admin wachtwoord geladen.');
		} else {
			console.warn('admin-password.txt is leeg, standaardwachtwoord actief!');
		}
	} catch (err) {
		console.warn('admin-password.txt niet gevonden, standaardwachtwoord actief:', err.message);
	}
}

loadAdminPassword();
setInterval(loadAdminPassword, 30000);

// ====================
// BLOCKED WORDS
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
	if (typeof text !== 'string') return text;
	let out = text;
	badWords.forEach(word => {
		if (!word) return;
		const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
		out = out.replace(new RegExp(escaped, 'gi'), '*'.repeat(word.length));
		const pattern = word
			.split('')
			.map(char => char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
			.join('[\\s._-]*');
		out = out.replace(new RegExp(pattern, 'gi'), '*'.repeat(word.length));
	});
	return out;
}

function containsBlockedNickname(text) {
	if (!text) return false;
	const normalizedNick = text.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]/g, '');
	for (const word of badWords) {
		const normalizedWord = word.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]/g, '');
		if (normalizedWord && normalizedNick.includes(normalizedWord)) return true;
	}
	return false;
}

function containsBadWord(text) {
	if (!text) return false;
	const normalized = text.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]/g, '');
	for (const word of badWords) {
		const normalizedWord = word.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]/g, '');
		if (normalizedWord && normalized.includes(normalizedWord)) return true;
	}
	return false;
}

loadBadWords();
setInterval(loadBadWords, 30000);

// ====================
// BAN SYSTEEM
// Opgeslagen in /data/bans.json
// Bevat: ip bans, device fingerprint bans, nick bans
// ====================

let bans = { devices: [], nicks: [] };

function loadBans() {
	try {
		bans = JSON.parse(fs.readFileSync('/data/bans.json', 'utf8'));
		bans.devices = bans.devices || [];
		bans.nicks = bans.nicks || [];
		console.log(`Loaded bans: ${bans.devices.length} devices, ${bans.nicks.length} nicks`);
	} catch (err) {
		bans = { ips: [], devices: [], nicks: [] };
	}
}

function saveBans() {
	try {
		fs.writeFileSync('/data/bans.json', JSON.stringify(bans, null, 2));
	} catch (err) {
		console.error('Failed to save bans:', err.message);
	}
}

function isDeviceBanned(fingerprint) {
	if (!fingerprint) return false;
	return bans.devices.includes(fingerprint);
}

function isNickBanned(nick) {
	return bans.nicks.map(n => n.toLowerCase()).includes(nick.toLowerCase());
}

function banUser(nick, fingerprint) {
	// Alleen device fingerprint + nick bannen, NOOIT het IP
	// Zo worden andere apparaten op hetzelfde wifi niet geblokkeerd
	if (fingerprint && !bans.devices.includes(fingerprint)) bans.devices.push(fingerprint);
	if (nick && !bans.nicks.map(n=>n.toLowerCase()).includes(nick.toLowerCase())) bans.nicks.push(nick);
	saveBans();
	console.log(`Banned: nick=${nick}, device=${fingerprint}`);
}

function unbanUser(nick) {
	bans.nicks = bans.nicks.filter(n => n.toLowerCase() !== nick.toLowerCase());
	// Zoek bijbehorende device op in actieve sessies
	const session = Object.values(activeSessions).find(s => s.nick && s.nick.toLowerCase() === nick.toLowerCase());
	if (session && session.fingerprint) {
		bans.devices = bans.devices.filter(d => d !== session.fingerprint);
	}
	saveBans();
	console.log(`Unbanned: nick=${nick}`);
}

loadBans();

// ====================
// 1 ACCOUNT PER IP + DEVICE TRACKING
// ====================

// Actieve sessies: socketId -> { nick, ip, fingerprint }
const activeSessions = {};

function getActiveDevice(fingerprint) {
	if (!fingerprint) return null;
	return Object.values(activeSessions).find(s => s.fingerprint === fingerprint);
}

// ====================
// SCHELD TRACKING (3 pogingen dan ban)
// ====================

const swearStrikes = {}; // nick -> count

function addSwearStrike(nick, fingerprint) {
	if (!swearStrikes[nick]) swearStrikes[nick] = 0;
	swearStrikes[nick]++;
	console.log(`Swear strike ${swearStrikes[nick]}/3 voor ${nick}`);

	if (swearStrikes[nick] >= 3) {
		banUser(nick, fingerprint);
		// Kick de gebruiker
		const socketId = Object.keys(activeSessions).find(id => activeSessions[id].nick === nick);
		if (socketId) {
			const targetSocket = io.sockets.sockets.get(socketId);
			if (targetSocket) {
				targetSocket.emit("force-login", "Je bent permanent verbannen wegens herhaaldelijk schelden.");
				targetSocket.disconnect(true);
			}
		}
		return true; // gebanned
	}

	// Waarschuw de gebruiker
	const socketId = Object.keys(activeSessions).find(id => activeSessions[id].nick === nick);
	if (socketId) {
		const targetSocket = io.sockets.sockets.get(socketId);
		if (targetSocket) {
			const remaining = 3 - swearStrikes[nick];
			targetSocket.emit("warn", `Waarschuwing: schelden is niet toegestaan. Nog ${remaining} kans(en) voor je verbannen wordt.`);
		}
	}
	return false;
}

// ====================

http.listen(port, function(){
	console.log("Starting server on port %s", port);
});

const users = [];
let msg_id = 1;

io.sockets.on("connection", function(socket){
	console.log("New connection!");

	var nick = null;
	const socketIp = socket.handshake.address;
	var deviceFingerprint = null;

	socket.on("login", function(data){

		// Fingerprint meegestuurd met login
		if (data.fingerprint && typeof data.fingerprint === 'string' && data.fingerprint.length < 200) {
			deviceFingerprint = data.fingerprint;
		}

		// Check device ban
		if (deviceFingerprint && isDeviceBanned(deviceFingerprint)) {
			socket.emit("force-login", "Je bent verbannen van deze chat.");
			socket.disconnect(true);
			return;
		}

		data.nick = data.nick.trim();
		data.nick = data.nick.replace(/[^a-zA-Z0-9_\-]/g, '').substring(0, 20);

		if (data.nick == "") {
			socket.emit("force-login", "Nick can't be empty.");
			return;
		}

		// Check nick ban
		if (isNickBanned(data.nick)) {
			socket.emit("force-login", "Je bent verbannen van deze chat.");
			socket.disconnect(true);
			return;
		}

		if (containsBlockedNickname(data.nick)) {
			socket.emit("force-login", "Deze gebruikersnaam bevat een geblokkeerd woord.");
			return;
		}

		// 1 account per apparaat (fingerprint) — meerdere apparaten op zelfde wifi werken gewoon
		if (deviceFingerprint) {
			const existingDeviceSession = getActiveDevice(deviceFingerprint);
			if (existingDeviceSession) {
				socket.emit("force-login", "Je bent al ingelogd op dit apparaat.");
				socket.disconnect(true);
				return;
			}
		}

		if (users.indexOf(data.nick) != -1) {
			socket.emit("force-login", "This nick is already in chat.");
			return;
		}

		nick = data.nick;
		users.push(data.nick);

		// Sla sessie op
		activeSessions[socket.id] = { nick, ip: socketIp, fingerprint: deviceFingerprint };

		console.log("User %s joined.", nick.replace(/(<([^>]+)>)/ig, ""));
		socket.join("main");

		io.to("main").emit("ue", { "nick": nick });
		socket.emit("start", { "users": users });
		socket.emit("previous-msg", { "msgs": messageCache });
	});

	// ====================
	// ADMIN COMMANDO'S
	// Stuur via: /admin <wachtwoord> ban <nick>
	//            /admin <wachtwoord> unban <nick>
	// Wachtwoord staat ALLEEN in de .env op de server
	// ====================
	socket.on("send-msg", function(data){

		if (nick == null) {
			socket.emit("force-login", "You need to be logged in to send message.");
			return;
		}

		let messageObject = data.m;

		// Check op admin commando
		if (messageObject && typeof messageObject.text === 'string') {
			const text = messageObject.text.trim();

			if (text.startsWith('/admin ')) {
				const parts = text.split(' ');
				// /admin <wachtwoord> <commando> <nick>
				const password = parts[1];
				const command = parts[2];
				const targetNick = parts[3];

				if (password !== ADMIN_PASSWORD) {
					socket.emit("warn", "Ongeldig wachtwoord.");
					return;
				}

				if (command === 'ban' && targetNick) {
					const targetSession = Object.values(activeSessions).find(s => s.nick && s.nick.toLowerCase() === targetNick.toLowerCase());
					banUser(
						targetNick,
						targetSession ? targetSession.fingerprint : null
					);
					// Kick de gebande gebruiker
					const targetSocketId = Object.keys(activeSessions).find(id => activeSessions[id].nick && activeSessions[id].nick.toLowerCase() === targetNick.toLowerCase());
					if (targetSocketId) {
						const targetSocket = io.sockets.sockets.get(targetSocketId);
						if (targetSocket) {
							targetSocket.emit("force-login", "Je bent verbannen door een beheerder.");
							targetSocket.disconnect(true);
						}
					}
					socket.emit("warn", `✅ ${targetNick} is verbannen.`);
					console.log(`Admin ban: ${targetNick} door ${nick}`);

				} else if (command === 'unban' && targetNick) {
					unbanUser(targetNick);
					socket.emit("warn", `✅ ${targetNick} is gedebanned.`);
					console.log(`Admin unban: ${targetNick} door ${nick}`);

				} else {
					socket.emit("warn", "Gebruik: /admin <wachtwoord> ban <nick> OF unban <nick>");
				}

				return; // Stuur admin commando NIET naar de chat
			}
		}

		// Normaal bericht — check op scheldwoorden
		if (
			messageObject &&
			typeof messageObject === "object" &&
			typeof messageObject.text === "string"
		) {
			const originalText = messageObject.text;
			const hasBadWord = containsBadWord(originalText);

			messageObject = {
				...messageObject,
				text: filterMessage(originalText)
			};

			// Als er een scheldwoord in zat, strike geven
			if (hasBadWord) {
				const session = activeSessions[socket.id];
				const banned = addSwearStrike(nick, session ? session.fingerprint : null);
				if (banned) return; // Gebruiker is nu verbannen, bericht niet sturen
			}
		}

		const msg = {
			"f": nick,
			"m": messageObject,
			"id": "msg_" + (msg_id++)
		}

		messageCache.push(msg);
		if (messageCache.length > cache_size) messageCache.shift();

		io.to("main").emit("new-msg", msg);
		console.log("User %s sent message.", nick.replace(/(<([^>]+)>)/ig, ""));
	});

	socket.on("typing", function(typing){
		if (nick != null) {
			socket.broadcast.to("main").emit("typing", { status: typing, nick: nick });
		}
	});

	socket.on("disconnect", function(){
		console.log("Got disconnect!");
		if (nick != null) {
			users.splice(users.indexOf(nick), 1);
			delete activeSessions[socket.id];
			delete swearStrikes[nick];
			io.to("main").emit("ul", { "nick": nick });
			console.log("User %s left.", nick.replace(/(<([^>]+)>)/ig, ""));
			socket.leave("main");
			nick = null;
		}
	});
});
