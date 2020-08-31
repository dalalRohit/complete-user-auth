/*
    Main Route file
*/
require("dotenv").config();

var express = require("express");
var router = express.Router();
var _ = require("lodash");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const redis = require("redis");
const client = redis.createClient();

//User model
const User = require("./../models/userModel");

//Middleware to check if the user is logged in or not
const { createTokens, auth } = require("./../utils/auth");
const { hashPassword } = require("./../utils/hash");

//Validation utils
const { regValidation, loginValidation } = require("./../utils/validation");

/*
  @POST /register
  @params : {username,email,password,password_confirm} as JSON 
*/
router.post("/register", async (req, res, next) => {
  let { username, email, password, password2 } = req.body;

  //validate the uesr
  const { error } = regValidation(req.body);
  if (error) {
    return res.status(400).json({ msg: error.details[0].message });
  }

  User.findOne({ username })
    .then(async (user) => {
      //If User found
      if (user) {
        if (user.email === email)
          return res.status(400).json({
            register: false,
            msg: `User with email ${email} and username ${username} already exists.`,
          });
        return res.status(400).json({
          register: false,
          msg: `User with username ${username} already exists!`,
        });
      } else {
        const secret = uuidv4();
        const newUser = new User({
          username,
          email,
          password,
          secret,
        });
        const hash = await hashPassword(newUser.password);
        if (hash) {
          newUser.password = hash;
        }
        await newUser.save();

        return res.status(201).json({ register: true, user: newUser._id });
      }
    })
    .catch((err) => {
      return res.status(400).json({ register: false, err });
    });
});

/* 
  @POST /login
  @params : {username,password} as JSON 
*/
router.post("/login", (req, res, next) => {
  let { username, password } = req.body;

  let { error } = loginValidation(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  User.findOne({ username }).then(async (user) => {
    if (!user) {
      return res
        .status(400)
        .json({ login: false, msg: `User not found! Check credentials.` });
    }

    const isPass = await bcrypt.compare(password, user.password);
    if (!isPass) {
      return res
        .status(400)
        .json({ login: false, msg: "Passwords do not match!" });
    }
    const { token, xToken } = await createTokens(user._id);
    try {
      await user.save();
      req.user = user;
      req.tokens = { token, xToken };
    } catch (err) {
      return res.status(400).json({ login: false, err });
    }

    //Send user with set HTTP cookies
    const options = {
      httpOnly: true,
      maxAge: 36 * 60 * 1000,
      secure: true,
      sameSite: true,
    };

    //Set cookies
    res.cookie("token", token, options);
    res.cookie("x-token", xToken, options);

    res.status(201).send({
      login: true,
      user: req.user["_id"],
      token: req.tokens.token,
      refreshToken: req.tokens.xToken,
    });
  });
});

/* 
  @GET /users
  @desc : List all stored users
  @access : Protected
*/
router.get("/users", auth, (req, res) => {
  User.find({}).then((users) => {
    res.status(200).json(users);
  });
});

/* 
  @POST /user/:id
  @params : user._id 
  @desc : Get a user with given "id"
  @access : Protected
*/
router.post("/user/:id", auth, (req, res) => {
  let { id } = req.params;
  User.findById({ _id: id })
    .then((user) => {
      if (user) {
        return res.json({ user: _.pick(user, ["_id", "username"]) });
      }
    })
    .catch(() => {
      res.status(400).json({ msg: "User not found" });
    });
});

/* 
  @GET /dashboard
  @desc : A sample protected route
  @access : Protected
*/
router.get("/dashboard", auth, (req, res) => {
  res.status(200).json({
    msg: "Success",
    desc: `Your dashboard ${req.user.id}`,
  });
});

/* 
  @GET /logout
  @params : JWT 'auth-token' as a request-header of a currently logged in session
  @access : Protected
*/
router.get("/logout", auth, async (req, res, next) => {
  const decoded = await jwt.decode(req.tokens.xToken);

  //https://github.com/NodeRedis/node-redis/issues/1000#issuecomment-655488752
  //setex(key,exp-time,val,cb())
  client.setex(req.tokens.xToken, decoded.exp, req.user.id, (err, data) => {
    if (err) {
      return res.status(500).json({
        logout: false,
        msg: err.message,
      });
    }
  });

  res.cookie("x-token", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.cookie("auth-token", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  req.user = {};
  req.tokens = {};

  return res.status(200).json({
    logout: true,
  });
});

/*
  @PUT /update/:id
  @params:
    User ID to update its password
    { new_password, new_password_confirm } as JSON
  @desc: Updates password of user with _id:id
  @access: Protected
*/
router.put("/update/:id", auth, (req, res, next) => {
  const { id } = req.params;
  const { new_password, new_password_confirm } = req.body;
  if (new_password !== new_password_confirm) {
    return res
      .status(400)
      .send({ update: false, msg: "New password should match" });
  }
  User.findById({ _id: id })
    .then(async (user) => {
      if (user) {
        user.password = await hashPassword(new_password);
        await user.save();

        return res
          .status(200)
          .json({ update: true, msg: "Password updated successfully" });
      }
    })
    .catch((err) => {
      res.status(400).json({ update: false, msg: "No user found" });
    });
});

module.exports = router;
