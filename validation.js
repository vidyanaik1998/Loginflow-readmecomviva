const Joi = require('joi');

const registerSchema = Joi.object({
  email: Joi.string().min(5).email(),
  password: Joi.string().min(2).max(255),
  fullname: Joi.string(),
  company: Joi.string(),
  phoneNumber: Joi.string().min(6).max(255),
});

const loginSchema = Joi.object({
    email:Joi.string().min(6).email(),
    password:Joi.string().min(6).max(255),
})


module.exports={registerSchema,loginSchema};