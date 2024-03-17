import { User } from "../models/userModel.mjs";
import { AppError } from "../utils/appError.mjs";
import { catchAsync } from "../utils/catchAsync.mjs";

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
  res.status(200).json({ status: "success", data: { name, phone, email } });
};

export const updateName = catchAsync(async (req, res, next) => {
  if (!req.body.name) return next(new AppError("Name missing or invalid. Please try again.", 401));

  setTimeout(async () => {
    try {
      let user = await User.findByIdAndUpdate(req.user._id, filterObj(req.body, "name"), {
        new: true,
        runValidators: true,
      });

      if (!user) return next(new AppError("Unable to update your account. Please log back in and try again.", 400));

      user = {
        userName: user.name,
        userEmail: user.email,
        userPhone: user.phone,
      };

      res.status(200).json({ status: "success", data: { user } });
    } catch (err) {
      console.log(err);
      res
        .status(401)
        .json({
          status: "failed",
          message:
            "Unable to update your account user name. Please try again with valid user name [a-zA-Z, Some Punctuation Allowed].",
        });
    }
  }, 2000);
});

export const updatePhone = catchAsync(async (req, res, next) => {
  if (!req.body.phone) return next(new AppError("Phone number missing or invalid. Please try again.", 401));

  setTimeout(async () => {
    try {
      let user = await User.findByIdAndUpdate(req.user._id, filterObj(req.body, "phone"), {
        new: true,
        runValidators: true,
      });

      if (!user) return next(new AppError("Unable to update your account. Please log back in and try again.", 400));

      user = {
        userName: user.name,
        userEmail: user.email,
        userPhone: user.phone,
      };

      res.status(200).json({ status: "success", data: { user } });
    } catch (err) {
      console.log(err);
      res.status(401).json({
        status: "failed",
        message: "Unable to update phone number. Please try again with valid phone number (xxx-xxx-xxxx).",
      });
    }
  }, 2000);
});

///////////////////////////////////////////////////////////////////////////////////////////////
//////////// ADMIN ONLY ROUTE HANDLERS - i.e. Routes with restrictTo('admin') /////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

export const getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({ status: "success", numUsers: users.length, data: { data: users } });
});

export const getUser = catchAsync(async (req, res, next) => {
  let user = await User.findOne({ email: req.body.userEmail });

  if (!user) return next(new AppError("No user found for the email provided.", 404));

  res.status(200).json({ status: "success", data: { data: user } });
});

export const updateNameAdmin = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, filterObj(req.body, "name"), {
    new: true,
    runValidators: true,
  });
  if (!user) return next(new AppError("No user found for the email provided.", 404));

  res.status(200).json({ status: "success", data: { data: user } });
});

export const updatePhoneAdmin = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, filterObj(req.body, "phone"), {
    new: true,
    runValidators: true,
  });
  if (!user) return next(new AppError("No user found for the email provided.", 404));

  res.status(200).json({ status: "success", data: { data: user } });
});

export const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, { active: false });

  if (!user) return next(new AppError("No user found for the email provided.", 404));

  res.status(200).json({ status: "success", message: "Successfully inactivated account." });
});

export const reactivateUser = catchAsync(async (req, res, next) => {
  const user = await User.findOneAndUpdate({ email: req.body.userEmail }, { active: true });

  if (!user) return next(new AppError("No user found for the email provided.", 404));

  res.status(200).json({ status: "success", message: "Successfully reactivated account." });
});
