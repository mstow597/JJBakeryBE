import express from 'express';
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
  updateEmail,
  displayResetPasswordPage,
} from '../controllers/authController.mjs';
import {
  getMe,
  updateMe,
  deleteMe,
  deleteUser,
  getAllUsers,
  getUser,
  updateUser,
  checkForEmailPassword,
} from '../controllers/userController.mjs';

const router = express.Router();

// Unprotected routes - no auth required
router.post('/signup', signup);
router.post('/login', login);
router.post('/forgotPassword', forgotPassword);
router.get('/resetPassword/:token', displayResetPasswordPage);
router.post('/resetPassword/:token', resetPassword);
router.post('/sendEmailVerification', sendEmailVerification);
router.get('/verifyEmail/:token', verifyEmail);

// Protected user routes - own profile access only.
router
  .route('/me')
  .post(protect, checkValidCSRFToken, getMe) // POST d/t csrfToken passed as hidden
  .patch(protect, checkValidCSRFToken, checkForEmailPassword, updateMe)
  .delete(protect, checkValidCSRFToken, deleteMe);
router.patch('/me/updatePassword', protect, checkValidCSRFToken, updatePassword);
router.patch('/me/updateEmail', protect, checkValidCSRFToken, updateEmail);

// Protected admin only routes
router.post('/', protect, restrictTo('admin'), checkValidCSRFToken, getAllUsers);
router
  .route('/:email')
  .post(protect, restrictTo('admin'), checkValidCSRFToken, getUser)
  .patch(protect, restrictTo('admin'), checkValidCSRFToken, checkForEmailPassword, updateUser)
  .delete(protect, restrictTo('admin'), checkValidCSRFToken, deleteUser);

export default router;
