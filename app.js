// to store the passwords and apikeys so,thet they can't be published
require("dotenv").config();
const express=require("express");
const bodyParser= require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const app=express();

// level 1 of encryption is simply storing user info in our database and validating it when the user logs in.

// level2 of encryption is done via mongoose-encryption.It scrambles the given message.
// const encrypt=require("mongoose-encryption");

// level3 of encryption is done via hashing.
// const md5=require("md5");

// Salting and hashing using bcrypt(level4).
// const bcrypt=require("bcrypt")

// level5 - authentication using passport
const session=require("express-session");
const passport=require("passport");
const passposrtlocalmongoose=require("passport-local-mongoose");
const googleStrategy=require("passport-google-oauth20").Strategy;
const findOrCreate=require("mongoose-findorcreate")



app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(express.static("public"));

app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}))
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://127.0.0.1:27017/userDB");


const userSchema=new mongoose.Schema({
    username:{
        type:String,
    },
    password:{
        type:String,
    },
    googleId:String,
    secret:String

});

userSchema.plugin(passposrtlocalmongoose)
userSchema.plugin(findOrCreate)

// mongoose encryption is used as an plugin to the schema
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User=mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user,done)=>{
    done(null,user.id)
});
passport.deserializeUser((id,done)=>{
    User.findById(id)
    .then((user)=>{
        done(null,user)
    })
});

passport.use(new googleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
))


app.get("/",function(req,res){
    res.render("home")
});

app.get("/auth/google",passport.authenticate("google",{scope:['profile']}))

app.get("/auth/google/secrets",passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.get("/submit",function(req,res){
   if (req.isAuthenticated){
    res.render("submit")
   }else{
    res.redirect("/login")
   }
});
app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret
    User.findById(req.user.id)
    .then((founditem)=>{
        founditem.secret=submittedSecret
        founditem.save()
        res.redirect("/secrets")
    })
    .catch((err)=>{
        console.log(err)
    });

})

app.route("/login")
.get((req,res)=>{
    res.render("login")
})
.post((req,res)=>{
    const username=req.body.username
    // // password first converted to hash and then compared to registered password hash.
    // // const password=md5(req.body.password)
    const password=req.body.password
    // User.findOne({email:email})
    // .then((founditem)=>{
    //     bcrypt.compare(password,founditem.password)
    //     .then((result)=>{
    //         if (result==true){
    //             res.render("secrets")
    //         }else{
    //             res.send("Incorrect Password!")
    //         }
    //     })
    //     .catch((err)=>{
    //         res.send(err)
    //     })
    // })
    // .catch((err)=>{
    //     res.send(err)
    // })

    const user=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.logIn(user,function(err){
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            })
        }
    })
})
        

app.get("/secrets",function(req,res){
   User.find({secret:{$ne:null}})
   .then((founditems)=>{
    res.render("secrets",{datas:founditems})
   })
})

app.route("/register")
.get(function(req,res){
    res.render("register")
})
.post((req,res)=>{
    // const email=req.body.username
    // // password stored as hash.
    // // const password=md5(req.body.password)
    const password =req.body.password

    // bcrypt.hash(password,Noofsaltrounds)
    // .then((hash)=>{
    //     const user=new User({
    //         email:email,
    //         password:hash
    //     })
    //     user.save()
    //     .then(()=>{ 
    //         res.render("secrets")
    //     })
    //     .catch((error)=>{
    //         res.send(error)
    //     })
    // })
    // .catch((err)=>{
    //     res.send(err)
    // })  


    User.register(new User({username:req.body.username}),password,function(err,user){
        if (err){
            console.log(err)
            res.redirect("/register")
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            })
        }
    })
});


app.get("/logout",function(req,res){
    req.logOut(function(err){
        console.log(err)
    });
    res.redirect("/")
})


app.listen(3000,function(){
    console.log("Server started on port 3000!")
})