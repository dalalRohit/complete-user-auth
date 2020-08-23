require("dotenv").config();
const _ = require("lodash");
const jwt = require("jsonwebtoken");
// const redis = require("redis");
// const client = redis.createClient();

const User = require("./../models/userModel");

//To generate tokens
const createTokens = async (userId) => {
  const token = jwt.sign({ _id: userId }, process.env.SECRET, {
    expiresIn: "1m",
  });
  return { token };
};

// const validateRefresh = async (refreshToken, userId) => {
//   const secret = process.env.REFRESH + process.env.SECRET;
//   let isExpired = false;
//   try {
//     jwt.verify(refreshToken, secret);
//   } catch (err) {
//     if (err.name === "TokenExpiredError") {
//       console.log("Refresh token expired..");
//       isExpired = true;
//     }
//     if (err.name !== "TokenExpiredError") {
//       return { msg: `refresh token invalid. ${err.message}..` };
//     }
//   }

//   const { token } = await createTokens(userId);
//   return {
//     newToken: token,
//     newXToken: refreshToken,
//   };
// };

//----------------------------Main export---------------------------------
const auth = async (req, res, next) => {
  console.log(
    "***************************Checking user auth******************************"
  );

  const token = req.header("auth-token");
  const xToken = req.header("x-token");
  var authDecoded = jwt.decode(token);

  if (!token || !xToken) {
    req.tokens = {};
    return res
      .status(403)
      .json({ auth: false, msg: "Access Denied. No Token Provided" });
  }

  //check for matching user
  const user = await User.findOne({ refresh: xToken });

  if (!user) {
    return res
      .status(400)
      .json({ auth: false, msg: "User not found. Invalid token" });
  }
  // if (xdecoded._id !== authDecoded._id) {
  //   return res.status(403).json({ auth: false, msg: "Users not matched.." });
  // }

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
      const { token } = await createTokens(authDecoded._id);

      res.header("x-token", xToken);

      //set user to the newly created userId
      const userNew = await jwt.decode(token);
      req.user = {
        id: userNew._id,
      };
      req.tokens = {
        token: token,
        xToken: xToken,
      };
      return next();
    }
  });
};

module.exports = {
  auth: auth,
  createTokens: createTokens,
};
