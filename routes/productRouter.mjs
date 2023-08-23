import express from 'express';
import { checkValidCSRFToken, protect, restrictTo } from '../controllers/authController.mjs';
import {
  addNewProduct,
  deleteProduct,
  getProduct,
  getProductNames,
  getProducts,
  getProductsByCategories,
  updateProduct,
} from '../controllers/productController.mjs';

const router = express.Router();

// Unprotected routes - no auth required
router.get('/:nextCursor?/:limit?', getProducts);
router.get('/single/:name', getProduct);
router.get('/names', getProductNames);
router.get('/filtered/:categories/:page?/:next_cursor?', getProductsByCategories);

// Admin only routes
router
  .route('/')
  .post(protect, restrictTo('admin'), checkValidCSRFToken, addNewProduct)
  .patch(protect, restrictTo('admin'), checkValidCSRFToken, updateProduct)
  .delete(protect, restrictTo('admin'), checkValidCSRFToken, deleteProduct);

export default router;
