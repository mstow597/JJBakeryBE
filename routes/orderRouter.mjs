import express from 'express';
import { restrictTo, protect, checkValidCSRFToken } from '../controllers/authController.mjs';
import {
  getMyPurchaseHistory,
  getShoppingCart,
  submitOrder,
  updateShoppingCart,
} from '../controllers/orderController.mjs';

const router = express.Router();

router.post('/', protect, checkValidCSRFToken, submitOrder);
router.patch('/', protect, checkValidCSRFToken, updateShoppingCart);
router.post('/me', protect, checkValidCSRFToken, getMyPurchaseHistory);
router.post('/me/shoppingcart', protect, checkValidCSRFToken, getShoppingCart);

export default router;
