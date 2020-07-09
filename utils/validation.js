/*
    A utility file for Registration and Login form/JSON data validation methods
*/

const Joi = require("@hapi/joi");

const regValidation = (regData) => {
  const registerSchema = Joi.object({
    username: Joi.string().required(),
    email: Joi.string()
      .required()
      .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } }),
    password: Joi.string().min(6).required(),
    password2: Joi.ref("password"),
  });
  return registerSchema.validate(regData);
};

const loginValidation = (loginData) => {
  const loginSchema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().min(6).required(),
  });

  return loginSchema.validate(loginData);
};

module.exports = {
  regValidation: regValidation,
  loginValidation: loginValidation,
};
