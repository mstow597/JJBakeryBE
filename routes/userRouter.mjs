import express from "express";
import {
  signup,
  protect,
  restrictTo,
  sendEmailVerification,
  verifyEmail,
  checkValidCSRFToken,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  displayResetPasswordPage,
  checkForEmailPassword,
  checkAndRefreshLogin,
  logout,
} from "../controllers/authController.mjs";
import {
  getMe,
  deleteUser,
  getAllUsers,
  getUser,
  reactivateUser,
  updateNameAdmin,
  updatePhoneAdmin,
  updateName,
  updatePhone,
} from "../controllers/userController.mjs";

const router = express.Router();

// Unprotected routes - no auth required
router.post("/signup", signup);
router.post("/login", login);
router.get("/logout", logout);
router.post("/checkAndRefreshLogin", protect, checkValidCSRFToken, checkAndRefreshLogin);
router.post("/forgotPassword", forgotPassword);
router.get("/resetPassword/:token", displayResetPasswordPage);
router.post("/resetPassword/:token", resetPassword);
router.post("/sendEmailVerification", sendEmailVerification);
router.get("/verifyEmail/:token", verifyEmail);

// Protected user routes - own profile access only.
router.post("/me", protect, checkValidCSRFToken, getMe);
router.patch("/me/name", protect, checkValidCSRFToken, checkForEmailPassword, updateName);
router.patch("/me/phone", protect, checkValidCSRFToken, checkForEmailPassword, updatePhone);
router.patch("/me/password", protect, checkValidCSRFToken, updatePassword);

// Protected admin only routes
router.post("/", protect, restrictTo("admin"), checkValidCSRFToken, getAllUsers);
router.post("/user", protect, restrictTo("admin"), checkValidCSRFToken, getUser);
router.post("/user/activate", protect, restrictTo("admin"), checkValidCSRFToken, reactivateUser);
router.patch("/user/name", protect, restrictTo("admin"), checkValidCSRFToken, checkForEmailPassword, updateNameAdmin);
router.patch("/user/phone", protect, restrictTo("admin"), checkValidCSRFToken, checkForEmailPassword, updatePhoneAdmin);
router.delete("/user", protect, restrictTo("admin"), checkValidCSRFToken, deleteUser);

export default router;
