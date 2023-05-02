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

app.get('/', (req,res) => {

    if (!req.session.authenticated) {
        var html = `
            <button onclick="location.href='/signup'">Sign up</button>
            <br>
            <button onclick="location.href='/login'">Log in</button>
        `
        res.send(html);
        return;
    }

    var name = req.session.name;

    console.log(name);

    res.send(`<h1>Hello ${name}</h1>
    <button onclick="location.href='/members'">Go to Members Area</button>
    <br>
    <button onclick="location.href='/logout'">Sign out</button>
    `);

});

app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/signupUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <br>
    <input name='email' type='email' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
        res.send(`
          <p>${message}</p>
          <a href="/signup">Return to sign up page.</a>
        `);
        return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword});
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
        res.send(`
          Invalid email/password combination.
          <a href="/login">Try again.</a>
        `);
        return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();

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
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.send(`
          Invalid email/password combination.
          <br>
          <a href="/login">Try again.</a>
        `);
        return;
	}
});


app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    var name = req.session.name;

    console.log(name);

    var image = Math.floor(Math.random() * 3) + 1;


    if (image == 1) {
        res.send(`
        <h1>Hello ${name}</h1>
        <img src='/fish.jpg' style='width:250px;'>
        <br>
        <button onclick="location.href='/logout'">Sign out</button>
        `
        );
    }

    else if (image == 2) {
        res.send(`
        <h1>Hello ${name}</h1>
        <img src='/lion.jpg' style='width:250px;'>
        <br>
        <button onclick="location.href='/logout'">Sign out</button>
        `
        );
    }
    else if (image == 3) {
        res.send(`
        <h1>Hello ${name}</h1>
        <img src='/robot.jpg' style='width:250px;'>
        <br>
        <button onclick="location.href='/logout'">Sign out</button>
        `
        );
    }

});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port + "!");
}); 