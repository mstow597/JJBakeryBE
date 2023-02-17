import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { catchAsync } from '../utils/catchAsync.mjs';
import { User } from '../models/userModel.mjs';
import { sendEmail } from '../utils/email.mjs';

export const restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array... example: ['admin', 'guide']
    if (!roles.includes(req.user.role))
      return next(new AppError('You do not have permission to perform this action.', 403));
    next();
  };
};

export const protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it exists
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return next(new AppError('You are not logged in. Please log in to get access', 401));

  // 2) Validate the token - verifying jwt signature
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    next(err);
  }

  // 3) Check if user still exists
  const user = await User.findById(decoded.id);
  if (!user) return next(new AppError('The user belonging to this token no longer exists.', 401));

  // 4) Check if user changed password after the JWT token was issued
  if (user.changedPasswordAfter(decoded.iat))
    return next(new AppError('Recently changed password! Please log in again.', 401));

  // 5) Everything checks out
  req.user = user;
  next();
});

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);
  // Be careful with this line of code - we cannot use the createSendToken function in a scenario where we would need the password to be set.
  user.password = undefined; //to prevent sending the password information back to the user
  res.status(201).json({ status: statusCode, data: { user: user, token } });
};

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
};

export const signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    phone: req.body.phone,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  createSendToken(newUser, 201, res);
});

export const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  // Check if email and password exist in req
  if (!email || !password) return next(new AppError('Missing email or password', 400));

  // Check if user exists and if password is correct
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Incorrect email or password', 401));

  // If everything checks out, send jwt to client.
  createSendToken(user, 200, res);
});

export const forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('Token sent to email!', 404)); // faking success to prevent account sniffing.

  // 2) Generate the random token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to the user's email
  const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to ${resetURL}\nIf you didn't forget your password, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 minutes).',
      message,
    });

    res.status(200).json({ status: 'success', message: 'Token sent to email!' });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later!', 500));
  }
});

export const resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ token: hashedToken, passwordResetExpires: { $gt: Date.now() } });

  // 2) If token has not expired and user exists, set new password
  if (!user) return next(new AppError('Token is invalid or has expired.', 400));
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for user - pre middleware in userModel.mjs

  // 4) Log the user in, send JWT to client
  createSendToken(user, 200, res);
});

export const updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from the collection
  const user = await User.findById(req.user._id).select('+password');

  // 2) Check if posted password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password)))
    return next(new AppError('Your current password is wrong.', 401));

  // 3) If password is correct, then update the password (note the middleware will handle the passwordChangedAt property for us)
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  // 4) Log the user in (send jwt).
  createSendToken(user, 200, res);
});
