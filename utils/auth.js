require("dotenv").config();
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
// const redis = require("redis");
// const client = redis.createClient();

// const User = require("./../models/userModel");

//To generate tokens
const createTokens = async (user) => {
  const token = jwt.sign({ _id: user }, process.env.SECRET, {
    expiresIn: "1m",
  });

  const xToken = jwt.sign(
    { _id: user, refresh: uuidv4() },
    process.env.REFRESH + process.env.SECRET,
    { expiresIn: "7d" }
  );

  return { token, xToken };
};

const validateRefresh = async (refreshToken, userId) => {
  const secret = process.env.REFRESH + process.env.SECRET;
  let isExpired = false;
  try {
    jwt.verify(refreshToken, secret);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      console.log("Refresh token expired..");
      isExpired = true;
    }
    if (err.name !== "TokenExpiredError") {
      return { msg: `refresh token invalid. ${err.message}..` };
    }
  }

  const tokens = await createTokens(userId);
  return {
    newToken: tokens.token,
    newXToken: isExpired ? tokens.xToken : refreshToken,
  };
};

//----------------------------Main export---------------------------------
const auth = async (req, res, next) => {
  console.log(
    "***************************Checking user auth******************************"
  );

  const token = req.header("auth-token");
  const xToken = req.header("x-token");
  var xdecoded = jwt.decode(xToken);
  var authDecoded = jwt.decode(token);

  if (!token || !xToken) {
    req.tokens = {};
    return res
      .status(403)
      .json({ auth: false, msg: "Access Denied. No Token Provided" });
  }

  //check for matching user
  if (xdecoded._id !== authDecoded._id) {
    req.tokens = {};
    return res.status(403).json({ auth: false, msg: "Users not matched.." });
  }

  jwt.verify(token, process.env.SECRET, async (err, user) => {
    //if auth-token is valid
    if (user) {
      req.user = {
        id: user._id,
      };
      req.tokens = {
        token,
        xToken,
      };
      return next();
    }

    //auth-token is invalid
    else if (err.name !== "TokenExpiredError") {
      req.tokens = {};
      return res
        .status(400)
        .json({ auth: false, msg: `Invalid auth-token. ${err.message}` });
    }

    //token is expired and create [auth,refresh] and send
    else if (err && err.name === "TokenExpiredError") {
      const newTokens = await validateRefresh(xToken, authDecoded._id);

      if (newTokens.newToken && newTokens.newXToken) {
        res.header("auth-token", newTokens.newToken);
        res.header("x-token", newTokens.newXToken);

        //set user to the newly created userId
        const userNew = await jwt.decode(newTokens.newToken);
        req.user = {
          id: userNew._id,
        };
        req.tokens = {
          token: newTokens.newToken,
          xToken: newTokens.newXToken,
        };
        return next();
      } else {
        return res.status(400).json({ auth: false, msg: newTokens.msg });
      }
    }
  });
};

module.exports = {
  auth: auth,
  createTokens: createTokens,
};
