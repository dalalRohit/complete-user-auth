/*
    Main Route file
*/

var express = require("express");
var router = express.Router();
var _ = require("lodash");
var bcrypt = require("bcryptjs");
const redis = require("redis");
const client = redis.createClient();

const updateData = (req, data) => {
  return {
    ...req,
    data,
  };
};

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
        const newUser = new User({
          username,
          email,
          password,
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
  @GET /user/:id
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
router.get("/logout", auth, async (req, res) => {
  try {
    res.cookie("x-token", "", {
      httpOnly: true,
      expires: new Date(0),
    });
    res.cookie("auth-token", "", {
      httpOnly: true,
      expires: new Date(0),
    });
    req.user = {};

    return res.status(200).json({ logout: true });
  } catch (err) {
    return res.status(401).json({ logout: false });
  }
});

/* 
  @GET /logoutall
  @params : JWT 'auth-token' as a request-header of a currently logged in session
  @desc : Logs out of all sessions across multiple devices
  @access : Protected
*/
router.get("/logoutall", auth, async (req, res) => {
  try {
    req.user.tokens = [];
    await req.user.save();

    res.status(200).json({ logoutAll: true });
  } catch (err) {
    res.status(500).send(err);
  }
});

/* 
  @GET /check
  @params : JWT 'auth-token' as a request-header of a currently logged in session
  @desc : Checks if the given token is valid or not
  @access : Protected
*/
router.get("/check", auth, async (req, res) => {
  let token = req.header("auth-token");
  if (!token) {
    return res.status(403).json({ msg: "Access denied" });
  }
  const user = await User.findOne({
    "tokens.token": token,
  });
  if (user) {
    return res.status(200).json({ user: true, id: user._id });
  } else {
    return res.status(403).json({ user: false });
  }
});

/*
  @PUT /update/:id
  @params:
    User ID to update its password
    { new_password, new_password_confirm } as JSON
  @desc: Updates password of user with _id:id
  @access: Protected
*/
router.put("/update/:id", (req, res, next) => {
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
