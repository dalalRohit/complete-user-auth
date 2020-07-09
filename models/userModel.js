require("dotenv").config();

const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

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
  tokens: [
    {
      token: {
        type: String,
        required: true,
      },
    },
  ],
});

UserSchema.methods.generateAuthToken = async function () {
  const user = this;
  const token = jwt.sign({ _id: user._id.toString() }, process.env.SECRET, {
    expiresIn: "7 days",
  });

  user.tokens = user.tokens.concat({ token });
  try {
    await user.save();
  } catch (err) {
    throw new Error(err);
  }
  return token;
};

var Users = mongoose.model("Users", UserSchema);

module.exports = Users;
