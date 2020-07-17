require("dotenv").config();
const _ = require("lodash");
const jwt = require("jsonwebtoken");

const User = require("./../models/userModel");

//To generate tokens
const createTokens = async (user) => {
  const token = jwt.sign({ user: user._id }, process.env.SECRET, {
    expiresIn: "2m",
  });

  const xToken = jwt.sign(
    { user: _.pick(user, ["_id", "date", "username"]) },
    process.env.REFRESH + user.password,
    { expiresIn: "7d" }
  );

  return Promise.all([token, xToken]);
};

const validateRefresh = async (refreshToken) => {
  let userId = -1;

  try {
    var xdecoded = jwt.decode(refreshToken);
  } catch (err) {
    return { msg: "Invalid x-auth token" };
  }

  userId = xdecoded.user._id;

  const user = await User.findById({ _id: userId });
  if (!user) {
    return { msg: "User not found" };
  }

  try {
    jwt.verify(refreshToken, process.env.REFRESH + process.env.SECRET);
  } catch (err) {
    if (err.name !== "TokenExpiredError") {
      return { msg: `x-token invalid. ${err.message}..` };
    }
  }

  const [newToken, newXToken] = await createTokens(user);
  return {
    newToken: newToken,
    newXToken: newXToken,
    user: user,
  };
};

//Main export
module.exports = async function (req, res, next) {
  console.log("Checking user auth");

  const token = req.header("auth-token");
  const xToken = req.header("x-token");

  if (!token || !xToken) {
    return res
      .status(403)
      .json({ auth: false, msg: "Access Denied. No Token Provided" });
  }
  try {
    const verified = jwt.verify(token, process.env.SECRET);

    var xdecoded = jwt.decode(xToken);
    var authDecoded = jwt.decode(token);

    if (xdecoded.user._id !== authDecoded._id) {
      return res
        .status(400)
        .json({ auth: false, msg: "Invalid tokens. Users not matched" });
    }
    req.user = { id: verified._id };
  } catch (err) {
    /*
      If not using refresh token, invalidate this request with 403
      will fail due to 1)Token expiry 2)Wrong secret 3)Changes in token from client side
      return res.status(400).json({ auth: false, msg: "Token auth failed" });
    */

    /* If using refresh token, here the access token is invalid so you have to :
      1. Validate refresh token
      2. Generate new pair of [accessToken,refreshToken] and send
    */
    if (err.name !== "TokenExpiredError") {
      return res
        .status(400)
        .json({ auth: false, msg: `Invalid auth-token. ${err.message}` });
    }

    const newTokens = await validateRefresh(xToken);

    if (newTokens.newToken && newTokens.newXToken) {
      res.header("auth-token", newTokens.newToken);
      res.header("x-token", newTokens.newXToken);
      req.user = _.pick(newTokens.user, ["id", "email"]);
    } else {
      return res.status(400).json({ auth: false, msg: newTokens.msg });
    }
  }

  return next();
};
