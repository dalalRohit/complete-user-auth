require("dotenv").config();

const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const _ = require("lodash");

var UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now(),
  },
});

UserSchema.methods.getTokens = async function () {
  const user = this;

  const token = jwt.sign({ _id: user._id }, process.env.SECRET, {
    expiresIn: "120000", //2m
  });

  const refreshToken = jwt.sign(
    { user: _.pick(user, ["_id", "date", "username"]) },
    process.env.REFRESH + process.env.SECRET,
    {
      expiresIn: "7d",
    }
  );

  return { token: token, refreshToken: refreshToken };
};

var Users = mongoose.model("Users", UserSchema);

module.exports = Users;
