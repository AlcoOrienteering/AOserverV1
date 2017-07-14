var app = require('express')();
var bodyParser = require('body-parser');
app.use(bodyParser.json());
var http = require('http').Server(app);
var port = process.env.PORT || 3000;

var uuid = require('uuid4');
var base64 = require('uuid-base64');

var firebase = require("firebase-admin");

var parseBearerToken = require('parse-bearer-token');

//var serviceAccount = JSON.parse(process.env['alcorienteering-18b6a-firebase-adminsdk-3plh3-bfcea0cc3b']);
// var serviceAccount = require("./alcorienteering-18b6a-firebase-adminsdk-3plh3-bfcea0cc3b.json");
var serviceAccount = {
	type: process.env.FB_type,
	project_id: process.env.FB_project_id,
	private_key_id: process.env.FB_private_key_id,
	private_key: process.env.FB_private_key,
	client_email: process.env.FB_client_email,
	client_id: process.env.FB_client_id,
	auth_uri: process.env.FB_auth_uri,
	token_uri: process.env.FB_token_uri,
	auth_provider_x509_cert_url: process.env.FB_auth_provider_x509_cert_url,
	client_x509_cert_url: process.env.FB_client_x509_cert_url
};

firebase.initializeApp({
  credential: firebase.credential.cert(serviceAccount),
  databaseURL: "https://alcorienteering-18b6a.firebaseio.com"
});

var uid;

function authenticate(req, succes, failed){
	var token = parseBearerToken(req);
	if (!token){
		failed("Missing header Authorization");
	} else {
		firebase.auth().verifyIdToken(token)
		  .then(function(decodedToken) {
			uid = decodedToken.uid;
			succes(uid);
		  }).catch(function(e){
			  var code = 400;
			  if (e.errorInfo.code === 'auth/argument-error') code = 401;
			  failed(e.errorInfo.message, code);
		  });
	}	
}

/*
var sessionsRef = firebase.database().ref("sessions");
sessionsRef.push({
  startedAt: firebase.database.ServerValue.TIMESTAMP
});

var database = firebase.database();

var adaNameRef = database.ref('users2');
var key = adaNameRef.push().key;
adaNameRef.push({ key: key, date: new Date(), first: 'Ada', last: 'Lovelace' });


var my_locRef = database.ref('my_location');
my_locRef.on('value', function(snapshot) {
  console.log(snapshot.val());
});

*/

var Client = require("mysql-pro");
var mysql = new Client({
    mysql: {
        host     : process.env.JAWSDB_HOST,
		user     : process.env.JAWSDB_USERNAME,
		password : process.env.JAWSDB_PASSWORD,
		database : process.env.JAWSDB_DBNAME
    }
});


app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

app.get('/client', function(req, res){
  res.sendFile(__dirname + '/client.html');
});


function authFailedResponse(res, msg = "User authentication failed.", code = 400){
	JsonResponseError(res, msg, code);
}

function JsonResponse(res, data){
	res.setHeader('Content-Type', 'application/json');
	res.send(JSON.stringify(data));
}

function JsonResponseError(res, msg, code){
	let r = {
		error: {
			message: msg
		}
	};
	res.setHeader('Content-Type', 'application/json');
	res.status(code).send(JSON.stringify(r));
}

/*
app.get('/api/v1/test/:uid', async function(req, res){
	
	console.log(req.url)
	var uid = req.params.uid;
	var user = await getUserByUID(uid);
	console.log(user);

});
*/

app.post('/api/v1/logout', function(req, res){
	
	JsonResponse(res, {success: true});

});

app.post('/api/v1/register/fcm', async function(req, res){
	
	//console.log(req.url)
	//console.log('USER', req.body.key);
	
	authenticate(req, async function(uid){

		var user = await getUserByUID(uid);
		//console.log('user 1', user);
		if (!user){			
			let result = await mysql.query('INSERT INTO users (uid) VALUES (?)', [uid]);
			let user_id = result.insertId;
			console.log('inserted user id', user_id);
			user = await getUserById(user_id);
			//console.log('user after insert', user);
		}
		var user_id = user.id;
		if(req.body.key){
			let result = await mysql.query('REPLACE INTO tokens (user_id, type, token) VALUES (?, ?, ?)', [user_id, 'FCM', req.body.key]);
			if(result.affectedRows){
				// This registration token comes from the client FCM SDKs.
				var registrationToken = req.body.key;

				// See the "Defining the message payload" section below for details
				// on how to define a message payload.
				var payload = {
				  data: {
					action: "registered"
				  }
				};

				// Send a message to the device corresponding to the provided
				// registration token.
				firebase.messaging().sendToDevice(registrationToken, payload)
				  .then(function(response) {
					// See the MessagingDevicesResponse reference documentation for
					// the contents of response.
					console.log("Successfully sent message:", response);
					JsonResponse(res, {success: true});
				  })
				  .catch(function(error) {
					console.log("Error sending message:", error);
					JsonResponse(res, {success: false});
				  });				
			} else {
				
			}
		} else {
			JsonResponse(res, {success: false});
		}
		
	}, function(err){
		authFailedResponse(res, err);
	});
});

app.post('/api/v1/races', function(req, res){		
	authenticate(req, async function(uid){
		let races = await getRaces();
		JsonResponse(res, {races: races});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/race/login', function(req, res){		
	authenticate(req, async function(uid){
		if(!req.body.code) {
			JsonResponseError(res, 'Missing parameter "Code".');
			return;
		}
		let race = await getRaceByTeamCode(req.body.code);
		JsonResponse(res, {race: race});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/race/checkpoints', function(req, res){		
	authenticate(req, async function(uid){
		if(!req.body.code) {
			JsonResponseError(res, 'Missing parameter "Code".');
			return;
		}
		let checkpoints = await getRaceCheckpointsByTeamCode(req.body.code);
		JsonResponse(res, {checkpoints: checkpoints});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/race/logout', function(req, res){		
	authenticate(req, async function(uid){
		JsonResponse(res, {success: true});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

/*
app.post('/api/v1/test', async function(req, res){
	
	let a = await getUsers();
	console.log(a);
	
	authenticate(req, async function(uid){
		
		console.log('UID', uid);
		
		let res = await mysql.query('SELECT * FROM users WHERE uid = ?', [uid]);
		var user = res[0];
		if (!user){
			let res = await mysql.query('INSERT INTO users (uid) VALUES (?)', [uid]);
			let uid = res.insertId;
			let res2 = await mysql.query('SELECT * FROM users WHERE uid = ?', [uid]);
			user = res2[0];
			console.log('USER', user);
		}
		
		let data = await x();
		JsonResponse(res, data);

	}, function(err, code){
		authFailedResponse(res, err, code);
	});

});
*/

async function getUsers(){
	let res = await mysql.query('SELECT * FROM users', []);
	return res;
}

async function getUserByUID(uid){
	let [res]  = await mysql.query('SELECT * FROM users WHERE uid = ?', [uid]);
	return res;
}

async function getUserById(id){
	let [res]  = await mysql.query('SELECT * FROM users WHERE id = ?', [id]);
	return res;
}

async function getRaces(){
	let res = await mysql.query('SELECT * FROM race', []);
	return res;
}

async function getRaceByTeamCode(code){
	let [race]  = await mysql.query('select r.*, t.code team_code, t.category team_category, t.start_timestamp team_start_timestamp from race r join teams t on t.race_id = r.id where t.code = ?', [code]);
	if(!race) return null;
	let [check]  = await mysql.query('select * from checkpoints where race_id = ? and type = ?', [race.id, 'START']);
	race.start = check;
	return race;
}

async function getRaceCheckpointsByTeamCode(code){
	let res = await mysql.query('select c.* from checkpoints c join teams t on t.race_id = c.race_id where t.code = ?', [code]);
	return res;
}


/*
async function insertTeam(race_id, name, category){	
	let code = generateTeamCode();
	let res = await mysql.query("
		IINSERT INTO teams (
			race_id,
			-- status,
			code,
			name,
			category
			-- start_timestamp
		) VALUES(?, ?, ?, ?)",
		[race_id, code, name, category]
	);
	return res;
}
*/

function generateTeamCode(){
	let u = uuid();
	return base64.encode(u);
}

http.listen(port, function(){
  console.log('listening on *:' + port);
  //console.log(generateTeamCode());
});
