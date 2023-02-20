import { User } from '../models/userModel.mjs';
import { AppError } from '../utils/appError.mjs';
import { catchAsync } from '../utils/catchAsync.mjs';

const filterObj = (obj, ...allowedFields) => {
  let newObject = {};
  Object.keys(obj).forEach((element) => {
    if (allowedFields.includes(element)) newObject[element] = obj[element];
  });
};

///////////////////////////////////////////////////////////////////////////////////////////////
//////////// USER ONLY ROUTE HANDLERS - i.e. Routes with restrictTo('admin') //////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

export const getMe = catchAsync(async (req, res, next) => {
  const { name, phone, email } = User.findById(req.user._id);
  res.status(200).json({ status: 'success', data: { name, phone, email } });
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
  // Not allowing admin to update user password
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'Not authorized to update user password. To reset password, user must initiate password reset POST request through /resetPassword (if user forgot password) or /updatePassword (if user logged in and wants to change password) route.'
      ),
      404
    );
  }

  // Not allowing admin to update email
  if (req.body.email || req.body.emailConfirm) {
    return next(
      new AppError(
        'Not authorized to update user email. If user is logged in and wishes to update email, have user use /updateEmail route. If user forgot email or lost access to email address, please contact database administrator for support.'
      ),
      404
    );
  }

  const user = await User.findOneAndUpdate(req.params.id, filterObj(req.body, 'name', 'phone', 'active'), {
    new: true,
    runValidators: true,
  });
  if (!user) return next(new AppError('No user found for given id'), 404);

  res.status(200).json({ status: 'success', data: { data: user } });
});

export const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate(req.params.id, { active: false }, { new: true, runValidators: false });
  if (!user) return next(new AppError('No user found for given id'), 404);

  res.status(200).json({ status: 'success', data: { data: user } });
});
