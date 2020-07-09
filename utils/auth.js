/*
    A utility function to check authentication of users by validating JWT token passed as Request header
*/


require("dotenv").config();
const User = require("./../models/userModel");

const jwt = require("jsonwebtoken");

module.exports = async function (req, res, next) {
  const token = req.header("auth-token");
  if (!token)
    return res
      .status(403)
      .json({ auth: false, msg: "Access Denied.Invalid Token" });

  try {
    const verified = jwt.verify(token, process.env.SECRET);
    const user = await User.findOne({
      _id: verified._id,
      "tokens.token": token,
    });
    if (!user) {
      return res
        .status(401)
        .json({ auth: false, msg: "Token expired. Login again!" });
    }
    req.user = user;
    req.token = token;

    return next();
  } catch (err) {
    res.status(403).json({ auth: false, msg: "Access Denied.Invalid Token" });
  }
};
