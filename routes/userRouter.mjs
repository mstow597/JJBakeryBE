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
router.post('/resetPassword/:token', resetPassword);
router.post('/verifyEmail', sendEmailVerification);
router.get('/verifyEmail/:token', verifyEmail);

// Protected user routes - own profile access only.
router
  .route('/me/:token')
  .get(protect, restrictTo('user'), checkValidCSRFToken, getMe)
  .patch(protect, restrictTo('user'), checkValidCSRFToken, checkForEmailPassword, updateMe)
  .delete(protect, restrictTo('user'), checkValidCSRFToken, deleteMe);

// Protected admin only routes
router.get('/:token', protect, restrictTo('admin'), checkValidCSRFToken, getAllUsers);
router
  .route('/:id/:token')
  .get(protect, restrictTo('admin'), checkValidCSRFToken, getUser)
  .patch(protect, restrictTo('admin'), checkValidCSRFToken, checkForEmailPassword, updateUser)
  .delete(protect, restrictTo('admin'), checkValidCSRFToken, deleteUser);

export default router;
