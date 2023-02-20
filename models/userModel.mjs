import mongoose from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, 'User must have a name.'],
    validate: {
      validator: function (value) {
        return validator.isAlpha(value.replace(/\s/g, ''));
      },
    },
  },
  email: {
    type: String,
    required: [true, 'User must have email address'],
    unique: true,
    validate: [validator.isEmail, 'Email is invalid. Please provide a valid email address'],
  },
  emailConfirm: {
    type: String,
    require: [true, 'You must confirm your email address'],
    validate: {
      validator: function (value) {
        return value === this.email;
      },
    },
  },
  phone: {
    type: String,
    required: true,
    validate: {
      validator: function (value) {
        return value.match(/^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/im);
      },
    },
  },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  password: {
    type: String,
    required: true,
    select: false,
    validate: {
      validator: function (value) {
        return validator.isStrongPassword(value, { returnScore: true }) >= 40;
      },
    },
  },
  passwordConfirm: {
    type: String,
    select: false,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function (value) {
        return this.password === value;
      },
      message: 'Passwords do not match.',
    },
  },
  passwordChangedAt: { type: Date },
  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },
  emailVerificationToken: { type: String },
  emailVerificationTokenExpires: { type: Date },
  verified: { type: Boolean, default: false }, // email verified ? authorized user : non authorized user
  active: { type: Boolean, default: true }, // active ? user has not been "deleted" : user has been "deleted"
});

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (!this.passwordChangedAt) return false;
  const changedTimeStamp = this.passwordChangedAt.getTime() / 1000;
  return JWTTimestamp < changedTimeStamp;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 min password reset token

  return resetToken;
};

userSchema.methods.createEmailVerificationToken = function () {
  const emailVerificationToken = crypto.randomBytes(32).toString('hex');
  this.emailVerificationToken = crypto.createHash('sha256').update(emailVerificationToken).digest('hex');
  this.emailVerificationTokenExpires = Date.now() + 10 * 60 * 1000; // 10 min verify email token

  return emailVerificationToken;
};

// All find like queries associated with User will go through this middleware first to select only active users
userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

userSchema.pre('save', async function (next) {
  // Only run this function if password was modified.
  if (!this.isModified('password')) return next();
  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  // Delete the passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now();
  next();
});
export const User = mongoose.model('User', userSchema);
