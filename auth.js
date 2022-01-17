const jwt = require('jsonwebtoken')
const validation = require('../helpers/validation')
const User = require('../Model/user')
const { v4: uuidv4 } = require('uuid')
const bcrypt = require('bcrypt')
const nodemailer = require('nodemailer')
const moment = require('moment');
const express = require("express")
const router= express.Router();
const readmelogin=require('../readme-login')
var util= require('util');
var encoder = new util.TextEncoder('utf-8');
const open = require('open');
const { http, https } = require('follow-redirects');

// const token = async (req,res) =>{
//     const accessToken =jwt.sign({
//         email:'test@test.com',
//     },`${process.env.SECRET_ACCESS_TOKEN}`,{expiresIn:`${process.env.ACCESS_TOKEN_EXPIRY}`});
//     res.send(accessToken);
// }



const login = async (req, res) => {
  

    try {
      const { error } = validation.loginSchema.validate(req.body);

      if (error) {
        res.status(400).json({
          status: 400,
          message: 'INPUT_ERRORS',
          errors: error.details,
          original: error._original,
        });
      } else {
        const user = await User.findOne({ email: req.body.email });
        const user_email = req.body.email;
        console.log("email1",user_email)
        const user_password = req.body.password;
        console.log("password1",user_password)


        const redirect_url=readmelogin(user_email,user_password)
        console.log("redirect url22",redirect_url)
        // open(redirect_url,{arguments:['--self']})
        

        console.log("testing window is exist",typeof window)
        // if (typeof window !== "undefined") {
        //  window.open('wwww.google.com')
        // }

        // Check if the email is correct
        if (user) {
          // Check if the password correct
          const validatePassword = await bcrypt.compare(req.body.password, user.password);

          if (validatePassword) {
            // Generate Access & Refresh Token
            const accessToken = jwt.sign({
              _id: user.id,
              username: user.username,
              email: user.email,
            }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
            const refreshToken = jwt.sign({
              _id: user.id,
              username: user.username,
              email: user.email,
            }, process.env.SECRET_REFRESH_TOKEN, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });

            console.log("accesstoken is :",accessToken)
            console.log("refreshtoken is :",refreshToken)

            if (await addRefreshToken(user, refreshToken)) {
              
             console.log("login sucess")
             
              res.status(200).json({ 
                success: {
                  status: 200,
                  message: 'LOGIN_SUCCESS',
                  accessToken: accessToken,
                  refreshToken: refreshToken,
                  url:redirect_url,
                  
                }
                
              
              }
              
              
              );
              
            } else {
              res.status(500).json({ error: { status: 500, message: 'SERVER_ERROR' } });
            }
            

          } else {
            res.status(403).json({ error: { status: 403, message: 'INVALID_CREDENTIALS' } });
          }
          
         
        } else {
          res.status(403).json({ error: { status: 403, message: 'INVALID_CREDENTIALS' } });
        }
        
        
      }
      
    } 
    catch (err) {
      console.log(err);
      res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
    }

  
  };


const register = async (req, res) => {
  try {
    const { error } = validation.registerSchema.validate(req.body, { abortEarly: false });
    if (error) {
      res.status(400).json({ status: 400, message: "Input_errors", errors: error.details, original: error._original });
    }
  
    
    else {
      
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);


      //create new user instance
      const user = new User({
      
        email: req.body.email,
        fullname: req.body.fullname,
        company: req.body.company,
        phoneNumber:req.body.phoneNumber,
        password: hashedPassword,
        emailConfirmed: false,
        emailToken: uuidv4(),
        security: {
          token: [],
          passwordReset: {
            token: null,
            provisionalPassword: null,
            expiry: null,
          },
        },

        // accessToken:accessToken,
        // refreshToken:refreshToken,
        // createdAt: new Date()

      });
      console.log("user created",user)
      //attemp to save the user in database
      await user.save();
      console.log("data saved to database")

      //genearte access token

      const accessToken = jwt.sign({
        _id: user.id,
        email: user.email,
      }, 'dn44HBHBJHD332jjddoapnrofs', { expiresIn: '15m' })

      console.log("access token generated sucessfully",accessToken)

      //refresh token 
      const refreshToken = jwt.sign({
        _id: user.id,
        email: user.email,
      }, `${process.env.SECRET_REFRESH_TOKEN}`, { expiresIn: `${process.env.REFRESH_TOKEN_EXPIRY}` })

      console.log("refrrsh token generated sucessfully",refreshToken)
      // readme integration

      const user_email = req.body.email;
      console.log("email1",user_email)
      const user_password = req.body.password;
      console.log("password1",user_password)

      const redirect_url=readmelogin(user_email,user_password)
      console.log("redirect url22",redirect_url)



      // Assign the token to user and save
      await User.updateOne({ email: user.email }, {
        
        $push: {
          'security.tokens': {
            accessToken: accessToken,
            refreshToken: refreshToken,
            createdAt: new Date(),
           


          }
        }

      })

      //send email confirmation

      await sendEmailconfirmation({ email: user.email, emailToken: user.emailToken })


      res.status(200).header().json({
        success: {
          status: 200,
          message: 'Register_sucess',
          accessToken: accessToken,
          refreshToken: refreshToken,
          readmeurl:redirect_url,
          user: {
            id: user.id,
            email: user.email
          },
        },
      })
    }

  } catch (err) {
    let errmsg;
    //err.keyPattern.email===1
    //User.findOne({email:req.body.email})
    if (User.findOne({ email: req.body.email })) {
      errmsg = "Email exists"
    } else {
      errmsg = err;
    }
    res.status(400).json({ errr: { status: 400, message: "errmsg" } });
  }
}

const token = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;

    //verify if the token is valid  -if not dont authorize ,ask to re-authenticate

    try {
      const decodeRefreshToken = jwt.verify(refreshToken, process.env.SECRET_REFRESH_TOKEN);
      const user = await User.findOne({ email: decodeRefreshToken.email });
      const existingRefreshToken = user.security.tokens;

      //check if refresh tokens is in document
      if (existingRefreshToken.some(token => token.refreshToken === refreshToken)) {
        //generate new access token
        const accessToken = jwt.sign({
          _id: user.id,
          email: user.email,
        }, `${process.env.SECRET_ACCESS_TOKEN}`, { expiresIn: `${process.env.ACCESS_TOKEN_EXPIRY}` })



        //send new acess token

        res.status(200).json({
          sucess: 200,
          message: 'Acess_token_geneerated',
          accessToken: accessToken,
        })
      } else {
        res.staus(401).json({ error: { status: 401, message: 'Invalid refresh token' } })
      }
    } catch (err) {
      res.staus(401).json({ error: { status: 401, message: 'Invalid refresh token' } })
    }

  } catch (err) {
    res.status(400).json({ error: { status: 400, message: "Bad request" } })
  }
}

const confirmEmailToken = async (req, res) => {
  // try{

  const emailToken = req.body.emailToken;

  if (emailToken != null) {

    const accessToken = req.header('Authorization').split(' ')[1];
    const decodedaccessToken = jwt.verify(accessToken, process.env.SECRET_ACCESS_TOKEN)

    //check if user exists
    const user = await User.findOne({ email: decodedaccessToken.email })

    //check if email is already confirmed
    if (!user.emailConfirmed) {
      //check if provided email token matched users email token
      if (emailToken === user.emailToken) {
        await User.updateOne({ email: decodedaccessToken.email }, { $set: { emailConfirmed: true, emailToken: null } })
        res.status(200).json({ success: { status: 200, message: 'Email _confirmed' } })
      }
      else {
        res.status(401).json({ error: { status: 401, message: 'invalid email token ' } })
      }
    } else {
      res.status(401).json({ error: { status: 401, message: 'email already confirmed ' } })
    }




  } else {
    res.status(400).json({ error: { status: 400, message: "bad request" } })
  }

  // }catch(err){
  //     res.status(400).json({error:{status:400,message:"bad request"}})
  // }
}

const resetPasswordConfirm = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    // Check if supplied passwordResetToken matches with the user's stored one
    if (user.security.passwordReset.token === req.body.passwordResetToken) {

      // Check if password reset token is expired
      if (new Date().getTime() <= new Date(user.security.passwordReset.expiry).getTime()) {
        await User.updateOne({ email: req.body.email }, {
          $set: {
            'password': user.security.passwordReset.provisionalPassword,
            'security.passwordReset.token': null,
            'security.passwordReset.provisionalPassword': null,
            'security.passwordReset.expiry': null,
          },
        });

        res.status(200).json({ success: { status: 200, message: 'PASSWORD_RESET_SUCCESS' } });
      } else {
        await User.updateOne({ email: req.body.email }, {
          $set: {
            'security.passwordReset.token': null,
            'security.passwordReset.provisionalPassword': null,
            'security.passwordReset.expiry': null,
          },
        });

        res.status(401).json({ error: { status: 401, message: 'PASSWORD_RESET_TOKEN_EXPIRED' } });
      }
    } else {
      res.status(401).json({ error: { status: 401, message: 'INVALID_PASSWORD_RESET_TOKEN' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
};

const resetPassword = async (req, res) => {
  try {
    if (req.body.provisionalPassword.length >= 6 && req.body.provisionalPassword.length <= 255) {
      // Hash Password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.provisionalPassword, salt);

      // Generate a password reset token
      const passwordResetToken = uuidv4();
      const expiresIn = moment().add(10, 'm').toISOString();

      // Update user with password token
      const user = await User.findOneAndUpdate({ email: req.body.email }, {
        $set: {
          'security.passwordReset': {
            token: passwordResetToken,
            provisionalPassword: hashedPassword,
            expiry: expiresIn,
          },
        },
      });

      await sendPasswordResetConfirmation({ email: req.body.email, passwordResetToken: passwordResetToken });

      res.status(200).json({ success: { status: 200, message: 'PASSWORD_RESET_EMAIL_SENT' } });
    } else {
      res.status(400).json({ error: { status: 400, message: 'PASSWORD_INPUT_ERROR' } });
    }
  } catch (err) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } });
  }
}
const transport = nodemailer.createTransport({
  host: process.env.NODEMAILER_HOST,
  port: process.env.NODEMAILER_PORT,
  auth: {
    user: process.env.NODEMAILER_USER,
    pass: process.env.NODEMAILER_PASS,
  },
});





const test = async (req, res) => {
  try {
    const newUser = new User({
      email: 'test2@test.com',
      password: 'test',
      emailConfirmed: false,
      emailToken: 'test',
      security: {
        token: null,
        passwordReset: null
      }
    })
    await newUser.save();
    res.send(newUser);

  } catch (err) {
    res.send(err);

  }

}


const addRefreshToken = async (user, refreshToken) => {
  try {
    const existingRefreshTokens = user.security.tokens;

    // Check if there less than 5
    if (existingRefreshTokens.length < 5) {
      await User.updateOne({ email: user.email }, {
        $push: {
          'security.tokens': {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        },
      });
    } else {
      // Otherwise, remove the last token
      await User.updateOne({ email: user.email }, {
        $pull: {
          'security.tokens': {
            _id: existingRefreshTokens[0]._id,
          },
        },
      });

      // Push the new token
      await User.updateOne({ email: user.email }, {
        $push: {
          'security.tokens': {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        },
      });
    }
    return true;
  } catch (err) {
    return false;
  }
};

const sendEmailconfirmation = async (user) => {

  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS
    },
  });

  const info = await transport.sendMail({
    from: '"Course test" <noreply@coursetest.com>',
    to: user.email,
    subject: 'confirm your email',
    text: `click the link to confirm your email:http://localhost:9000/confirm-email/${user.emailToken}`,
  })

}

const sendPasswordResetConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  const info = await transport.sendMail({
    from: '"Course Test" <noreply@coursetest.com>',
    to: user.email,
    subject: 'Reset Your Password',
    text: `Click the link to confirm your password reset: http://localhost:9000/confirm-password/${user.passwordResetToken}`,
  });
};

// module.exports ={test,token};
module.exports = { test, login, register, token, confirmEmailToken, resetPassword, resetPasswordConfirm };