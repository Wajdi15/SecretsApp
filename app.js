//jshint esversion:6
require("dotenv").config(); // Storing configuration in the environment separate from code
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption")
//const md5 = require("md5")// for hashing data
//const bcrypt = require("bcrypt"); //A library to help you hash passwords and salting it
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var GoogleStrategy = require("passport-google-oauth20").Strategy; //OAuth 2.0
const findOrCreate = require("mongoose-findorcreate");
const { static, Router } = require("express");

const app = express();
app.set("view engine", "ejs");
app.use(static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
//START USING session
app.use(
  session({
    secret: "our little secret", //This is the secret used to sign the session ID cookie.
    resave: false, //Forces the session to be saved back to the session store
    saveUninitialized: false, //Forces a session that is "uninitialized" to be saved to the store.
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
});
mongoose.set("useCreateIndex", true); // fix error
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); //to add this function

// string we will use it to encrypt : process.env.SECRET
//plugin for add some package for the schema
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields : ["password"]})// encryptedFields is for encrypt only certain fields

const User = mongoose.model("User", userSchema);
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy()); // create a local login strategy

passport.serializeUser(User.serializeUser()); //to create
passport.deserializeUser(User.deserializeUser()); // to get data
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    //passport
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
      } else {
        User.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
  });
app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })

  .post((req, res) => {
    //passprt-local-mongoose
    User.register(
      { username: req.body.username },
      req.body.password,
      (err, user) => {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } }, (err, foundUser) => {
      if (err) {
        console.log(err);
      } else if (foundUser) {
        res.render("secrets", { userWithSecret: foundUser });
      }
    });
  } else {
    res.redirect("/login");
  }
});
app
  .route("/submit")
  .get((req, res) => {
    res.render("submit");
  })
  .post((req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, (err, foundUser) => {
      if (err) {
        console.log(err);
      } else if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save();
        res.redirect("/secrets");
      }
    });
  });

app.get("/logout", (req, res) => {
  req.logout(); //Invoking logout() will remove the req.user property and clear the login session (if any).
  res.redirect("/");
});
app.listen(3000, () => {
  console.log("server started on port 3000.");
});
