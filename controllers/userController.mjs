import { User } from '../models/userModel.mjs';
import { AppError } from '../utils/appError.mjs';
import { catchAsync } from '../utils/catchAsync.mjs';

const filterObj = (obj, ...allowedFields) => {
  let newObject = {};
  Object.keys(obj).forEach((element) => {
    if (allowedFields.includes(element)) newObject[element] = obj[element];
  });
  return newObject;
};

///////////////////////////////////////////////////////////////////////////////////////////////
//////////// USER ONLY ROUTE HANDLERS - i.e. Routes with restrictTo('user') ///////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

export const getMe = (req, res, next) => {
  const { name, phone, email } = req.user;
  res.status(200).json({ status: 'success', data: { name, phone, email } });
};

export const updateMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.user._id, filterObj(req.body, 'name', 'phone'), {
    new: true,
    runValidators: true,
  });

  if (!user) return next(new AppError('Unable to update your account. Please log back in and try again.', 400));

  res.status(200).json({ status: 'success', data: { user } });
});

export const deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.user._id, { active: false, csrfTokenExpires: new Date(0) });

  if (!user) return next(new AppError('Unable to inactivate your account. Please log back in and try again.'));

  const cookieOptions = {
    expires: new Date(0),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', '', cookieOptions);
  res.cookie('csrf', '', cookieOptions);
  res.status(200).json({ status: 'success', message: 'Successfully inactivated your account.' });
});

///////////////////////////////////////////////////////////////////////////////////////////////
//////////// ADMIN ONLY ROUTE HANDLERS - i.e. Routes with restrictTo('admin') /////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

export const getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({ status: 'success', numUsers: users.length, data: { data: users } });
});

export const getUser = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.userEmail });

  if (!user) return next(new AppError('No user found for the email provided.', 404));

  res.status(200).json({ status: 'success', data: { data: user } });
});

export const updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, filterObj(req.body, 'name', 'phone'), {
    new: true,
    runValidators: true,
  });
  if (!user) return next(new AppError('No user found for the email provided.', 404));

  res.status(200).json({ status: 'success', data: { data: user } });
});

export const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, { active: false });

  if (!user) return next(new AppError('No user found for the email provided.', 404));

  res.status(200).json({ status: 'success', message: 'Successfully inactivated account.' });
});

export const reactivateUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, { active: true });

  if (!user) return next(new AppError('No user found for the email provided.', 404));

  res.status(200).json({ status: 'success', message: 'Successfully reactivated account.' });
});
