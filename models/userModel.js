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
  secret: {
    type: String,
    unique: true,
  },
});

UserSchema.methods.getTokens = async function () {
  const user = this;

  const token = jwt.sign({ _id: user._id }, process.env.SECRET, {
    expiresIn: "2m", //2m
  });

  const refreshToken = jwt.sign(
    { user: user._id },
    process.env.REFRESH + process.env.SECRET,
    {
      expiresIn: "7d",
    }
  );

  return { token, refreshToken };
};

var Users = mongoose.model("Users", UserSchema);

module.exports = Users;
