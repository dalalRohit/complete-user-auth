/*
    A utility function to generate hash passwords
*/

var bcrypt = require("bcryptjs");

const hashPassword = async (pswd) => {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(pswd, salt);
  return hash;
};

module.exports = {
  hashPassword: hashPassword,
};
