// Bring the the mongoose package
const mongoose = require('mongoose');

// Bring mongoose-unique-validator to use in the Schema as validator
// pre-save validation for unique fields within a Mongoose schema
const uniqueValidator = require('mongoose-unique-validator');

// pbkdf2 algorithm 
const crypto = require('crypto');

// Bring the json web token
// essentially the password to your JWT's
const jwt = require('jsonwebtoken');

// bring the secert from the config file
const secret = require('../config').secret;

// Create the user Schema with the following definitions, and also add the time stamp
const UserSchema = new mongoose.Schema({
  username: {
    type: String, 
    lowercase: true, unique: true, 
    required: [true, "can't be blank"], 
    match: [/^[a-zA-Z0-9]+$/, 'is invalid'], 
    index: true
  },

  email: {
  type: String, 
  lowercase: true, 
  unique: true, 
  required: [true, "can't be blank"], 
  match: [/\S+@\S+\.\S+/, 'is invalid'], 
  index: true},
  bio: String,
  bio: String,
  image: String,
  hash: String,
  salt: String
}, {timestamps: true});

// pre-save validation for unique fields within a Mongoose schema
// configuring the validator's message
UserSchema.plugin(uniqueValidator, {message: 'is already taken.'});


// Create the hash by hasing the password that has been giving by the user
UserSchema.methods.setPassword = function(password) {
  this.salt = crypto.randomBytes(16).toString('hex');
  // pbkdf2Sync generate hashes
  // password, the iteration (number of times to hash the password), the length (how long the hash should be), and the algorithm
  this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
};

// Hash the passing passworld and compare it with the stored hash for that user
UserSchema.methods.validPassword = function(password) {
  const hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
  return this.hash === hash;
};

UserSchema.methods.generateJWT = function() {
  const today = new Date();
  const exp = new Date(today);
  // set the experation date to be after 60 days
  exp.setDate(today.getDate() + 60);

  // payload which is what the token will contain (contains the claims)
  return jwt.sign({
    id: this._id,
    username: this.username,
    exp: parseInt(exp.getTime() / 1000),
  }, secret);
};

// get the JSON representation of the user that will be passed to the front-end during authentication
UserSchema.methods.toAuthJSON = function() {
  return {
    username: this.username,
    email: this.email,
    token: this.generateJWT(),
    bio: this.bio,
    image: this.image
  };
};

// create the model and name it
mongoose.model('User', UserSchema);