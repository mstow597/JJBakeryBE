import express from 'express';
import { signup, protect, restrictTo, sendEmailVerification, verifyEmail } from '../controllers/authController.mjs';
import { deleteUser, getAllUsers, getUser, updateUser } from '../controllers/userController.mjs';

const router = express.Router();

// Unprotected routes - no auth required
router.route('/signup').post(signup);
router.route('/forgotPassword');
router.route('/resetPassword/:token');
router.route('/verifyEmail').post(sendEmailVerification);
router.route('/verifyEmail/:token').get(verifyEmail);

// Protected routes - accessible only by users, own profile only.
router.use(protect, restrictTo('user'));
router.route('/getMe');
router.route('/updateMe');
router.route('/deleteMe');

router.use(protect, restrictTo('admin'));
router.route('/').get(getAllUsers);
router.route('/:id').get(getUser);
router.route('/update/:id', updateUser);
router.route('/delete/:id', deleteUser);

export default router;
