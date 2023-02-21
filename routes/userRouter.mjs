import express from 'express';
import {
  signup,
  protect,
  restrictTo,
  sendEmailVerification,
  verifyEmail,
  checkValidCSRFToken,
  login,
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
router.route('/forgotPassword');
router.route('/resetPassword/:token');
router.post('/verifyEmail', sendEmailVerification);
router.get('/verifyEmail/:token', verifyEmail);

// Protected user routes - own profile access only.
router.get('/getMe/:token', protect, restrictTo('user'), checkValidCSRFToken, getMe);
router.patch('/updateMe/:token', protect, restrictTo('user'), checkValidCSRFToken, checkForEmailPassword, updateMe);
router.delete('/deleteMe/:token', protect, restrictTo('user'), checkValidCSRFToken, deleteMe);

// Protected admin only routes
router.get('/:token', protect, restrictTo('admin'), checkValidCSRFToken, getAllUsers);
router.get('/:id/:token', protect, restrictTo('admin'), checkValidCSRFToken, getUser);
router.patch(
  '/update/:id/:token',
  protect,
  restrictTo('admin'),
  checkValidCSRFToken,
  checkForEmailPassword,
  updateUser
);
router.delete('/delete/:id/:token', protect, restrictTo('admin'), checkValidCSRFToken, deleteUser);

export default router;
