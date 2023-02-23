import path from 'path';
import * as url from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { catchAsync } from '../utils/catchAsync.mjs';
import { User } from '../models/userModel.mjs';
import { sendEmail } from '../utils/email.mjs';
import { AppError } from '../utils/appError.mjs';

const __fileName = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__fileName);

/**
 * @param user
 * @param statusCode
 * @param res
 * @description
 * - Function utilized at the end login middleware.
 * - Generates JWT and CSRF tokens and sends as cookies to end user.
 * - Stores CSRF token/expiry in DB for validating route authorization.
 * - JWT encode expiry date/time and user ID - extracted within protect middleware function.
 * @returns undefined (sends response to user)
 */
const createSendTokens = catchAsync(async (user, statusCode, res) => {
  const token = signToken(user._id);
  const csrfToken = crypto.randomBytes(32).toString('hex');
  user.csrfToken = crypto.createHash('sha256').update(csrfToken).digest('hex'); // has csrf token for storagein database
  user.csrfTokenExpires = new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000);
  await user.save({ validateBeforeSave: false });

  const cookieOptions = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);
  res.cookie('csrf', csrfToken, cookieOptions);
  user.password = undefined; //to prevent sending the password information back to the user - we are not saving, no updates made to DB
  res.status(201).json({ status: statusCode, data: { user: user, token, csrfToken } });
});

/**
 *
 * @param {*} id
 * @description
 * - Utilizes the jsonwebtoken npm library to generate JWT to send to user
 * - Utilizes the user._id, the primary key for User documents in the User collection (MongoDB)
 * - Utilizes a secret key (environment variable)
 * - Encodes an expiration time in the options object (setting expiresIn)
 * @returns String (Json Web Token - JWT)
 */
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
};

/**
 *
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} statusCode status code for response (200 for email, 201 for new user)
 * @param {*} option enum: ['email', 'password', 'newUser']
 * @description
 * - Utilized by /users/signup, /users/forgotPassword, and /users/sendEmailVerification routes.
 * - Dynamically generates an email link sent to the user email account. Link will be for email verification or password reset as determined by value of option parameter.
 * - When NODE_ENV === 'test', returning simple message without sending email d/t email limits (max 100 per month for testing per mailtrap.io)
 * @returns undefined (sends response to user)
 */
const generateAndSendLink = async (req, res, statusCode, option) => {
  let token, message, html, URL;

  const user = await User.findOne({ email: req.body.email });
  if (!user) res.status(statusCode).json({ status: 'success', message: 'Link sent to email!' }); // protection from account sniffing

  const routeType = option === 'email' || option === 'newUser' ? 'verifyEmail' : 'resetPassword';
  if (option === 'email' || option === 'newUser') {
    token = user.createEmailVerificationToken();
    URL = `${req.protocol}://${req.get('host')}/api/v1/users/${routeType}/${token}`;
    message = `To verify your email, please click the link below to submit a GET request to the following URL: ${URL}. If you did not initiate this request, please ignore this email.`;
    html = `<h2>Verify Your Email<h2><p>To verify your email please click the link below:</p><br /><a href="${URL}">Verify Email</a>`;
    await user.save({ validateBeforeSave: false });
  } else if (option === 'password') {
    token = user.createPasswordResetToken();
    URL = `${req.protocol}://${req.get('host')}/api/v1/users/${routeType}/${token}`;
    message = `To reset your password, please click the link below to submit a GET request to the following URL: ${URL}. If you did not initiate this rquest, please ignore this email!`;
    html = `<h2>Reset Your Password<h2><p>To reset your password please click the link below:</p><br /><a href="${URL}">Reset Password</a>`;
    await user.save({ validateBeforeSave: false });
  }

  const responseMessage =
    option === 'newUser'
      ? `You're account was successfully created. Prior to accessing you account, you must verify your email address with the link provided in a message sent to your email address`
      : 'Link sent to email!';

  if (process.env.NODE_ENV === 'test')
    return res.status(statusCode).json({ status: 'success', message: responseMessage + '(NODE_ENV test only)' });

  try {
    const linkType = option === 'email' || option === 'newUser' ? 'email verification' : 'password reset';
    await sendEmail({
      email: user.email,
      subject: `Your ${linkType} link (valid for 10 minutes).`,
      message,
      html,
    });

    res.status(statusCode).json({ status: 'success', message: responseMessage });
  } catch (err) {
    if (option === 'email' || option === 'newUser') {
      user.verificationToken = undefined;
      user.verificationTokenExpires = undefined;
      await user.save({ validateBeforeSave: false });
    } else if (option === 'password') {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
    }
    return next(new AppError('There was an error with your request. Please retry again later!.'));
  }
};

/**
 *
 * @param  {...any} roles Accepts an array of string arguments where each argument is a role defined in the User schema
 * @description
 * - Returns Express route middleware function to limit a route to a particular role (admin or user).
 * - This middleware should be placed before other middleware functions.
 * @returns middleware function (express)
 */
export const restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array... example: ['admin', 'user']
    if (!roles.includes(req.user.role))
      return next(new AppError('You do not have permission to perform this action.', 403));
    next();
  };
};

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by /api/v1/users/signup POST route.
 * - Uses the following properties within req object to create a user from the User mongoose model/schema: name, email, emailConfirm, phone, password, passwordConfirm.
 * - Any additional properties passed to request body will be ignored (i.e. user cannot set role, emailVerify token, etc.)
 * - Following user creation, an emailVerificationToken (and expiry) is generated and attached to new user using the createEmailVerificationToken() user instance method.
 * - The emailVerificationToken is sent via email to the user's email address used during creation. This includes a link to verify email address for improved user experience.
 * - The user must confirm his/her email prior to using the account (security).
 * @returns undefined (invokes next() middleware function)
 */
export const signup = catchAsync(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    emailConfirm: req.body.emailConfirm,
    phone: req.body.phone,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  user.emailConfirm = undefined;
  await user.save({ validateBeforeSave: false });

  await generateAndSendLink(req, res, 201, 'newUser');

  // const verificationToken = user.createEmailVerificationToken();

  // const verifyURL = `${req.protocol}://${req.get('host')}/api/v1/users/verifyEmail/${verificationToken}`;
  // const message = `To verify your email, please copy and paste the following URL into your browser: ${verifyURL}. If you did not sign up for an account, please ignore this email.`;
  // const html = `<h2>Verify Your Email<h2><p>To verify your email please click the link below:</p><br /><a href="${verifyURL}">Verify Email</a>`;

  // if (!(process.env.NODE_ENV === 'test')) {
  //   try {
  //     await sendEmail({
  //       email: user.email,
  //       subject: 'Your password reset token (valid for 10 minutes).',
  //       message,
  //       html,
  //     });
  //   } catch (err) {
  //     user.verificationToken = undefined;
  //     user.verificationTokenExpires = undefined;
  //     await user.save({ validateBeforeSave: false });

  //     return next(
  //       new AppError(
  //         'There was an error sending the email verification. Please retry a POST request at {{URL}}/api/v1/users/verifyEmail with email in body.'
  //       )
  //     );
  //   }
  // }

  // res.status(201).json({
  //   status: 'success',
  //   data: {
  //     name: user.name,
  //     email: user.email,
  //     message: `${user.name}, you're account was successfully created. Prior to accessing you account, you must verify your email address with the link provided in a message sent to your email address: ${user.email}.`,
  //   },
  // });
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by the /api/v1/users/verifyEmail POST route.
 * - Expects: req.body = { email: _email_ }
 * - In the event the user's emailVerificationToken has expired or if the email failed to send, this email will generate an emailVerificationToken/expiry and resend email to user.
 * @returns undefined (invokes next() middleware function)
 */
export const sendEmailVerification = catchAsync(async (req, res, next) => {
  await generateAndSendLink(req, res, 200, 'email');
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by the /api/v1/users/verifyEmail/:token GET route
 * - This function hashes the emailVerificationToken acquired via req.params.token (request parameter).
 * - The hashed emailVerificationToken is used find the matching user in the database (database stores emailVerificationToken as hashed value)
 * - Query also ensures emaiLVerificationTokenExpires is greater than current date/time (i.e. checking if token expired).
 * - If conditions are met, the user is verified (user.verified = true) and emailVerificationToken/expiry removed from DB.
 * @returns undefined (invokes next() middleware function)
 */
export const verifyEmail = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpires: { $gt: Date.now() },
  });
  if (!user) return next(new AppError('Verification token invalid or has expired', 400));

  user.verified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).sendFile(path.join(__dirname, '../private/html/emailVerified.html'));
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by the /api/v1/users/login POST route
 * - Expects: req.body = { email: _userEmail_, password: _userPassword_ }
 * - User acquired from DB using req.body.email.
 * - User verified using the correctPassword user instance method to hash the password passed in req.body and compare to password stored in DB.
 * - User must be a verified user (email verified).
 * - If all conditions met, create and send JWT and CSRF tokens via createSendTokens() function.
 * @returns undefined (invokes next() middleware function)
 */
export const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) return next(new AppError('Missing email or password', 400));

  const user = await User.findOne({ email }).select('+password');
  if (!user || !user.verified || !(await user.correctPassword(password, user.password)))
    return next(
      new AppError('Incorrect email or password, or email not verified (must be verified to access account).', 401)
    );

  createSendTokens(user, 200, res);
});

/**
 * @param req Express middleware request object
 * @param res Express middleware response object
 * @param next Express middleware next object
 * @description
 * - Retrieves the JavaScript Web Token (JWT) from req.headers.authorization.
 * - Verifies the jwt signature (match + not expired), decoding and extracting the User Id
 * - Query database using User Id obtained in step 2 to find the user.
 * - Checks if password changed after the JWT token was issued.
 * - If successfully meets all requirements, set req.user to the queried user in step 3.
 * @returns undefined (Note: call is made to next() pass handle to next middleware function in line)
 */
export const protect = catchAsync(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer'))
    token = req.headers.authorization.split(' ')[1];
  if (!token) return next(new AppError('You are not logged in. Please log in to get access', 401));

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    next(err);
  }

  const user = await User.findById(decoded.id);
  if (!user) return next(new AppError('The user belonging to this token no longer exists.', 401));

  if (user.changedPasswordAfter(decoded.iat))
    return next(new AppError('Recently changed password! Please log in again.', 401));

  req.user = user;
  console.log(req.user);
  next();
});

/**
 *
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Middleware function for defense against CSRF (cross-site-request-forgery) attacks.
 * - All HTTP routes dealing with acquiring, updating, deleting, or otherwise handling of user data MUST be filtered through this middleware function.
 * - Extracts the CSRF token from the URL route parameter and hashes it for comparison with hashed CSRF token in DB.
 * - Checks and compares CSRF token expiration with current date/time.
 * - If conditions are satisfied, call next() to pass control to next middleware function.
 * @returns undefined
 */
export const checkValidCSRFToken = (req, res, next) => {
  const hashedParamToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const { csrfToken } = req.user;
  if (!(hashedParamToken === csrfToken) || req.user.csrfTokenExpires < Date.now())
    return next(new AppError('Unauthorized request. Please log back into your account to refresh your tokens.'));
  next();
};

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by the /api/v1/users/forgotPassword POST route
 * - Expects req.body = { email: _userEmail_ }
 * - Behaves similar to verifyEmail except with passwordResetToken/expiry.
 * - Submits email with link to user email to reset password (link points to the /api/v1/users/resetPassword/:token POST route).
 * @returns undefined (invokes next() middleware function)
 */
export const forgotPassword = catchAsync(async (req, res, next) => {
  generateAndSendLink(req, res, 200, 'password');
});

export const displayResetPasswordPage = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } });

  if (!user) return next(new AppError('Token is invalid or has expired.', 400));
  res.status(200).sendFile(path.join(__dirname, '../private/html/resetPassword.html'));
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by /api/v1/users/resetPassword:token POST route
 * - Expects req.body={password: _newPassword_, passwordConfirm: _newPassword_}
 * - Function verifies hashed req.params.token matches resetToken stored in DB and expiry greater than current date/time
 * - If conditions met, update password and remove passwordResetToken/expiry
 * - Note: the pre('save') middleware automatically updates the changedPasswordAt property fo given user.
 * @returns undefined (invokes next() middleware function)
 */
export const resetPassword = catchAsync(async (req, res, next) => {
  console.log(req.body);
  if (!req.body.password || !req.body.passwordConfirm)
    return next(
      new AppError(
        'Request body missing password and/or passwordConfirm. Please try again with both fields in the request.'
      )
    );
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } });

  if (!user) return next(new AppError('Token is invalid or has expired.', 400));
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  res.status(200).json({ status: 'success', message: 'Password successfully reset.' });
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by /api/v1/users/me/updatePassword/:token POST route
 * - Expects req.body = { passwordCurrent: _userCurrentPassword_ , password: _newPassword_ , passwordConfirm: _newPassword_ }
 * - Compares req.body.passwordCurrent to current user's password using correctPassword instance method.
 * - If condition satisfied, set new password and password confirm, save user, send new JWT and CSRF tokens to user.
 * - Note: pre('save') middleware functions will set passwordChangedAt property, hash new password, and remove passwordConfirm automatically
 * @returns undefined (invokes next() middleware function)
 */
export const updatePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id).select('+password');

  if (!(await user.correctPassword(req.body.passwordCurrent, user.password)))
    return next(new AppError('Your current password is wrong.', 401));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  res.status(200).json({ status: 'success', message: 'Password updated successfully.' });
});

/**
 * @param {*} req Express middleware request object
 * @param {*} res Express middleware response object
 * @param {*} next Express middleware next object
 * @description
 * - Utilized by /api/v1/users/me/updateEmail/:token POST route
 * @returns undefined (invokes next() middleware function)
 */
export const updateEmail = catchAsync(async (req, res, next) => {
  if (!req.body.email || !req.body.emailConfirm || !req.body.password)
    return next(
      new AppError(
        'Cannot update email. Missing one or more of: email, emailConfirm, password. Please resubmit will all of the required fields.'
      )
    );

  if (!(await req.user.correctPassword(req.body.password, req.user.password)))
    return next(new AppError('Incorrect password. Please resubmit with your correct password.'));

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { email: req.body.email, emailConfirm: req.body.emailConfirm },
    { runValidators: true }
  );

  res.status(200).json({ status: 'success', data: { user: updatedUser } });
});
