var app = require('express')();
var bodyParser = require('body-parser');
app.use(bodyParser.json());
var http = require('http').Server(app);
var port = process.env.PORT || 3000;

var uuid = require('uuid4');
var base64 = require('uuid-base64');

var moment = moment = require('moment-timezone');
moment.tz.setDefault('Europe/Prague');

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
		database : process.env.JAWSDB_DBNAME,
		dateStrings: 'date'
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

function JsonResponseError(res, msg, code = 400){
	let r = {
		error_body: {
			message: msg
		}
	};
	res.setHeader('Content-Type', 'application/json');
	res.status(code).send(JSON.stringify(r));
}

function JsonResponseCheckpoints(res, checkpoints, code, error = ''){
	let r = {
	  "checkpoints": checkpoints,
	  "error_body": {
		"success": (error === ''),
		"id": code,
		"message": error
	  }
	};
	res.setHeader('Content-Type', 'application/json');
	res.status(error === '' ? 200 : 400).send(JSON.stringify(r));
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
	authenticate(req, async function(uid){
		var user = await getUserByUID(uid);
		if(user) {
			let result = await mysql.query('DELETE FROM tokens WHERE user_id = ?', [user.id]);
			JsonResponse(res, {success: true});
		} else {
			JsonResponseError(res, 'User not found');
		}			
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
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
		
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/races', function(req, res){		
	authenticate(req, async function(uid){
		try{
			let user = await getUserByUID(uid);
			var races = await getRacesByUserId(user.id);			
		} catch (e){
			console.log(e)
		}
		JsonResponse(res, {races: races});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/public/races', async function(req, res) {
	try {
		var races = await getRaces();
	} catch (e) {
		console.log(e);
	}
	JsonResponse(res, { races: races });
});

app.post('/api/v1/race', function(req, res){		
	authenticate(req, async function(uid){
		if(!req.body.code) {
			JsonResponseError(res, 'Missing parameter "Code".');
			return;
		}
		let race = await getRaceByTeamCode(req.body.code, uid);		
		JsonResponse(res, {race: race});
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/race/checkpoints', function(req, res){		
	authenticate(req, async function(uid){
		if(!req.body.code) {
			JsonResponseCheckpoints(res, [], 101, 'Missing parameter "Code".');
			return;
		}
		var code = req.body.code;
		var team = await getTeamByCode(code);
		if(!team){
			JsonResponseCheckpoints(res, [], 102, 'Team not found.');
			return;
		}
		if((team.status !== 'FINISHED' && team.status !== 'DNS' && team.status !== 'DSQ' && team.status !== 'ACCEPTED' && team.status !== 'RUNNING') || moment().add(2, 'seconds').isBefore(moment.tz(team.start_timestamp, 'Europe/Prague'))){
			JsonResponseCheckpoints(res, [], 103, 'Checkpoints are not yet available for this team.');
			return;
		}
		if(team.status == 'ACCEPTED'){
			await updateTeamStatus('RUNNING', team.id);
		}		
		var checkpoints = await getRaceCheckpointsByTeamCode(code);
		JsonResponseCheckpoints(res, checkpoints, 0);
	}, function(err, code){
		authFailedResponse(res, err, code);
	});
});

app.post('/api/v1/race/checkpoint/visited', function(req, res){		
	authenticate(req, async function(uid){
		if(!req.body.checkpoint_id) {
			JsonResponseCheckpoints(res, [], 101, 'Missing parameter "Checkpoint ID".');
			return;
		}
		var checkpoint_id = req.body.checkpoint_id;
		let user = await getUserByUID(uid);
		// TODO: kontrola jestli je race running a muye se do nej zapisovat
		
		var [team] = await mysql.query(`
			select t.* from participants p 
			join teams t on t.id = p.team_id
			join race r on r.id = t.race_id
			join checkpoints c on c.race_id = r.id
			where c.id = ? and p.user_id = ?`,
			[checkpoint_id, user.id]
		);
		if(!team){
			JsonResponseError(res, 'Team or checkpoint does not exist, or you are not signed for this race!');
		}
		if(team.status !== 'RUNNING'){
			JsonResponseError(res, 'You have not started yet!');
		}
		try{
			let result = await setCheckpointVisited(checkpoint_id, user.id);
			JsonResponse(res, {success: true});
		} catch (e){
			JsonResponseError(res, 'Checkpoint has been already visited!');
		}
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

app.post('/api/v1/admin/verify', function (req, res) {
    authenticate(req, async function (uid) {
        if (await verifyAdmin(uid)) {
            JsonResponse(res, { success: true });
        } else {
			JsonResponseError(res, 'You do not have sufficient permissions to access this API.', 403);        
		}
    }, function (err, code) {
        authFailedResponse(res, err, code);
    });
});

app.post('/api/v1/admin/team', function (req, res) {
    authenticate(req, async function (uid) {
        if (await verifyAdmin(uid)) {
			if(!req.body.code) {
				JsonResponseError(res, 'Missing parameter "Code".');
				return;
			}
			var code = req.body.code;
			var team = await getTeamByCode(code);
			if(!team){
				JsonResponseError(res, 'Team not found.');
				return;
			}	
			// TODO: realne hodnoty z DB
            JsonResponse(res, {
			  "team_info": {
				"name": "Borci",
				"status": "REGISTERED",
				"category": "MEN",
				"start_timestmap": "2017-09-09 20:00:00",
				"team_members": [
				  {
					"email": "m@l.cz",
					"birth_date": "1997-05-29 00:00:00", // at to ma zase stejny format
					"full_name": "Martin Lank"
				  },
				  {
					"email": "v@l.cz",
					"birth_date": "1992-02-25 00:00:00",
					"full_name": "Vojta Lank"
				  }
				]
			  }
			});
        } else {
			JsonResponseError(res, 'You do not have sufficient permissions to access this API.', 403);        
		}
    }, function (err, code) {
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

async function verifyAdmin(uid) {
    let user = await getUserByUID(uid);
    if (user && user.role === 'ADMIN') {
        return true;
    }
    return false;
}

async function getRaces(){
	let res = await mysql.query('SELECT * FROM race', []);
	return res;
}

async function getTeamByCode(code){
	let [res] = await mysql.query('SELECT * FROM teams WHERE code = ?', [code]);
	return res;
}

async function updateTeamStatus(status, id){
	let res = await mysql.query('UPDATE teams SET status = ? WHERE id = ?', [status, id]);
	return res ? res.affectedRows : null;
}

async function setCheckpointVisited(checkpoint_id, user_id){
	let res = await mysql.query(`
		INSERT INTO participant_checkpoints 
		(checkpoint_id, participant_id, timestamp)
		VALUES (?, ?, ?)`, [checkpoint_id, user_id, moment().format('YYYY-MM-DD HH:mm:ss')]);
	return res ? res.affectedRows : null;
}

async function getRacesByUserId(id) {
	let res = await mysql.query(
		`select
			r.*,
			r.status race_status,
			t.code team_code,
			t.name team_name,
			t.status team_status,
			t.category team_category,
			t.start_timestamp team_start_timestamp,
			u.email partner_email,
			u.name partner_name
		from race r
		join teams t
			on t.race_id = r.id
		join participants p
			on p.team_id = t.id
		join participants p2
			on p2.team_id = t.id
		join users u 
			on u.id = p2.user_id and u.id != p.user_id
		where p.user_id = ?`,
		[id]
	);
	return res;
}

async function getRaceByTeamCode(code, uid) {
	let [race] = await mysql.query(
		`select
			r.*,
			r.status race_status,
			t.code team_code,
			t.name team_name,
			t.status team_status,
			t.category team_category,
			t.start_timestamp team_start_timestamp,
			COALESCE(t.finish_timestamp, 0) team_finish_timestamp,
			u.email partner_email,
			u.name partner_name
		from race r
		join teams t
			on t.race_id = r.id
		join participants p
			on p.team_id = t.id
		join users u 
			on u.id = p.user_id
		where t.code = ?
			and u.uid != ?
		`,
		[code, uid]
	);
	if (!race) return null;
	let [check] = await mysql.query(
		`select
			*
		from checkpoints
		where race_id = ?
			and type = ?`,
		[race.id, 'START']
	);
	race.start = check;
	return race;
}

async function getRaceCheckpointsByTeamCode(code) {
	let res = await mysql.query(
		`select
			c.*,
            TIME_TO_SEC(TIMEDIFF((
			select timestamp from participant_checkpoints pc 
            join participants p on p.user_id = pc.participant_id 
            where pc.checkpoint_id = c.id and p.team_id = t.id 
            order by timestamp asc limit 1), t.start_timestamp)) as visited
		from checkpoints c
		join teams t
			on t.race_id = c.race_id
		where t.code = ?`,
		[code]
	);
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
