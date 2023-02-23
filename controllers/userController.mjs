import { User } from '../models/userModel.mjs';
import { AppError } from '../utils/appError.mjs';
import { catchAsync } from '../utils/catchAsync.mjs';

export const checkForEmailPassword = (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm || req.body.email || req.body.emailConfirm)
    return next(new AppError('Not allowed to update password nor email with this route.'), 404);
  next();
};

const filterObj = (obj, ...allowedFields) => {
  let newObject = {};
  Object.keys(obj).forEach((element) => {
    if (allowedFields.includes(element)) newObject[element] = obj[element];
  });
};

///////////////////////////////////////////////////////////////////////////////////////////////
//////////// USER ONLY ROUTE HANDLERS - i.e. Routes with restrictTo('user') ///////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

export const getMe = (req, res, next) => {
  const { name, phone, email } = req.user;
  res.status(200).json({ status: 'success', data: { name, phone, email } });
};

export const updateMe = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate(req.user._id, filterObj(req.body, 'name', 'phone'), {
    new: true,
    runValidators: true,
  });

  if (!user) return next(new AppError('Unable to update your account. Please log back in and try again.'));

  res.status(200).json({ status: 'success', data: { user } });
});
export const deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate(req.user._id, { active: false });

  if (!user) return next(new AppError('Unable to inactivate your account. Please log back in and try again.'));

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
  const user = await User.find(req.params.id);

  if (!user) return next(new AppError('No user found for given id.'), 404);

  res.status(200).json({ status: 'success', data: { data: user } });
});

export const updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate(req.params.id, filterObj(req.body, 'name', 'phone'), {
    new: true,
    runValidators: true,
  });
  if (!user) return next(new AppError('No user found for given id'), 404);

  res.status(200).json({ status: 'success', data: { data: user } });
});

export const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate(req.params.id, { active: false });

  if (!user) return next(new AppError('No user found for given id'), 404);

  res.status(200).json({ status: 'success', message: 'Successfully inactivated account.' });
});
