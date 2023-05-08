require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require("joi");

const port = process.env.PORT || 5000;

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized - 403"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {

    if (!req.session.authenticated) {
        res.render("notLoggedIn");
        return;
    }

    var name = req.session.name;
    res.render("index", {name: name})

});

app.get('/signup', (req,res) => {
    res.render("signup");
});

app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/signupUser', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
			name: Joi.string().required(),
            email:Joi.string().required(),
			password: Joi.string().required()
		});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
        const missing = validationResult.error.details[0].context.label;
        const message = `Please provide a valid ${missing}.`;
        res.render("signupFailed", {message:message});
        return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: "user"});
	console.log("Inserted user.");

    const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();

    req.session.authenticated = true;
	req.session.email = email;
    req.session.name = result[0].name;
	req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});


app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        res.render("loginFailed");
        return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1, user_type: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("User not found");
		res.redirect("/login");
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("Correct password.");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.render("loginFailed");
        return;
	}
});


app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    var name = req.session.name;
    res.render("members", {name:name});

});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1, user_type: 1}).toArray();

    res.render("admin", {users: result});
});


app.post('/promote/:name', async (req, res) => {
    const name = req.params.name;

    await userCollection.updateOne({ name: name }, { $set: { user_type: 'admin' } });
    
    res.redirect('/admin');
});

app.post('/demote/:name', async (req, res) => {
    const name = req.params.name;

    await userCollection.updateOne({ name: name }, { $set: { user_type: 'user' } });
    
    res.redirect('/admin');
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port + "!");
}); 