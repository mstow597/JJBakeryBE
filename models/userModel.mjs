import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "User must have a name."],
    validate: {
      validator: function (value) {
        return validator.isAlphanumeric(value.replaceAll(/[\s-]/g, ""));
      },
    },
  },
  email: {
    type: String,
    required: [true, "User must have email address"],
    lowercase: true,
    unique: true,
    validate: [validator.isEmail, "Email is invalid. Please provide a valid email address"],
  },
  emailConfirm: {
    type: String,
    required: [true, "You must confirm your email address"],
    lowercase: true,
    validate: {
      validator: function (value) {
        return value === this.email;
      },
    },
  },
  emailChangedAt: { type: Date },
  previousEmails: [String],
  phone: {
    type: String,
    required: [true, "User must have phone number"],
    validate: {
      validator: function (value) {
        // return value.match(/^\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?$/);
        return /^\(?(\d{3})\)?[- ]?(\d{3})(\ -\ )?(\d{4})$/.test(value);
      },
    },
  },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  password: {
    type: String,
    required: [true, "User must have password"],
    select: false,
    validate: {
      validator: function (value) {
        return validator.isStrongPassword(value);
      },
    },
  },
  passwordConfirm: {
    type: String,
    select: false,
    required: [true, "Please confirm your password"],
    validate: {
      validator: function (value) {
        return this.password === value;
      },
      message: "Passwords do not match.",
    },
  },
  passwordChangedAt: { type: Date },
  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },
  emailVerificationToken: { type: String },
  emailVerificationTokenExpires: { type: Date },
  csrfToken: { type: String },
  csrfTokenExpires: { type: Date },
  verified: { type: Boolean, default: true }, // email verified ? authorized user : non authorized user --- change this back to false when mailtrap is enabled for email verification
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

userSchema.methods.changedEmailAfter = function (JWTTimestamp) {
  if (!this.emailChangedAt) return false;
  const changedTimeStamp = this.emailChangedAt.getTime() / 1000;
  return JWTTimestamp < changedTimeStamp;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto.createHash("sha256").update(resetToken).digest("hex");
  this.passwordResetExpires = Date.now() + Number(process.env.TOKEN_EXPIRATION);
  return resetToken;
};

userSchema.methods.createEmailVerificationToken = function () {
  const emailVerificationToken = crypto.randomBytes(32).toString("hex");
  this.emailVerificationToken = crypto.createHash("sha256").update(emailVerificationToken).digest("hex");
  this.emailVerificationTokenExpires = Date.now() + Number(process.env.TOKEN_EXPIRATION);
  return emailVerificationToken;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////// Test only instance methods ////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

if (process.env.NODE_ENV === "test") {
  userSchema.methods.setRole = async function (role) {
    this.role = role;
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setEmailVerifyTokenRandom = async function () {
    this.emailVerificationToken = crypto
      .createHash("sha256")
      .update(crypto.randomBytes(32).toString("hex"))
      .digest("hex");
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setEmailVerifyTokenToExpired = async function () {
    this.emailVerificationTokenExpires = new Date(Date.now() - 10000);
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setPasswordResetTokenToExpired = async function () {
    this.passwordResetExpires = new Date(Date.now() - 10000);
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setCSRFTokenToExpired = async function () {
    this.csrfTokenExpires = new Date(Date.now() - 10000);
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setVerifiedTrue = async function () {
    this.verified = true;
    this.emailVerificationToken = undefined;
    this.emailVerificationTokenExpires = undefined;
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setActiveFalse = async function () {
    this.active = false;
    await this.save({ validateBeforeSave: false });
  };

  userSchema.methods.setPasswordChangedAtCurrentTime = async function () {
    this.passwordChangedAt = new Date(Date.now() - 10000);
    await this.save({ validateBeforeSave: false });
  };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////// Pre/Post Middleware /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

userSchema.pre("save", async function (next) {
  this.emailConfirm = undefined;

  if (!this.isModified("password")) return next(); // isModified(<arg>) always returns true for NEW documents

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = Date.now();
  next();
});

export const User = mongoose.model("User", userSchema);
