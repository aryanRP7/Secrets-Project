import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();


app.use(
  session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 //will active session for 60 seconds.
    //If you not defined cookie time and if in browser if you change tab then also cookie will be saved but if you closed entire browser session will expire if you want session to not expire even if browser is closed define cookie maxmim age. Here cookie will be saved on basis of defined(here 30 sec).
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});



app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req,res)=>{
  req.logout((err)=>{
    if (err){
      console.log(err);
    }else{res.redirect("/");
          }
  })
});

app.get("/submit", (req,res)=>{
  if (req.isAuthenticated()){
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
  });


app.post("/submit", async (req,res) =>{
  const secret = req.body.secret;
  console.log(req.user);
  try{
    await db.query("UPDATE users SET secret = $1 WHERE email = $2",[secret,req.user.email]);
    res.redirect("/secrets")
  }catch (err){
    console.log(err);
  }
})

app.get("/auth/google",
  passport.authenticate("google",{
    scope:["profile","email"]}));

app.get("/auth/google/secrets", passport.authenticate("google", {
      successRedirect: "/secrets",
      failureRedirect: "login",
    }));

app.get("/secrets", async (req,res)=>{
  if(req.isAuthenticated()){
    try{
      const result = await db.query("SELECT * FROM users WHERE email = $1",[req.user.email]);
      const Yoursecret = result.rows[0].secret;
      if(Yoursecret){
        res.render("secrets.ejs", {secret:Yoursecret}) //in place of secrets.ejs line 08 secret we are placing our secret
      } else res.render("secrets.ejs",{secret:"गंगाधर ही शक्तिमान है...!"});
    } catch (err){
      console.log(err);
    }
  }
});


app.post("/login", passport.authenticate("local",{ //passport is going to trigger the strategy which we defined at end and telling we are using local strategy in order to authenticate the perticular resuest.
successRedirect: "/secrets",
failureRedirect:"/login"
})
);


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    
    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
            );
            const user = result.rows[0];
            req.login(user,(err)=>{
              console.log(err);
              res.redirect("/secrets");
            });
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
  });

passport.use("local", // here user will be verified and directed to "/secrets"
new Strategy(async function verify(username,password,cb){
  try{ //no need to req username #bodyparser will automates for us (by comparing name attribute in ejs file)
    const result = await db.query("SELECT * FROM users WHERE email = $1",[username]);
    if(result.rows.length > 0){
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password , storedHashedPassword , (err,result) => {
        if (err){
          return cb(err)
        } else {
          if (result){
            return cb(null,user); //null means no error and user when we go to "/secrets" user isAuthenticated will be True
          } else {
            return cb(null, false) //means when we go to "/secrets" user isAuthenticated will be false
          }
        }
      })
    } else {
      return cb("User not found")
    }
  } catch (err){
    return cb(err);
  }
}));


passport.use("google",
new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken , profile , cb) =>{
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email])
    if (result.rows.length == 0){
      const newUser = await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[profile.email,"google"])
      cb (null,newUser.rows[0]);
    } else { //user already exists
            cb (null, result.rows[0])
    }
  } catch (err){console.log(err);}
}) )

passport.serializeUser((user,cb)=>{
  cb(null,user);
});
passport.deserializeUser((user,cb)=>{
  cb(null,user)
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
