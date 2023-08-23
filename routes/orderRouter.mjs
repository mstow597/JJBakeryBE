import express from "express";
import {
  restrictTo,
  protect,
  checkValidCSRFToken,
} from "../controllers/authController.mjs";
import {
  getMyPurchaseHistory,
  getShoppingCart,
  submitOrderUser,
  submitOrderGuest,
  updateShoppingCart,
} from "../controllers/orderController.mjs";

const router = express.Router();

router.post("/submit", submitOrderGuest);
router.post("/me/submit", protect, checkValidCSRFToken, submitOrderUser);
router.post("/me/update", protect, checkValidCSRFToken, updateShoppingCart);
router.post("/me", protect, checkValidCSRFToken, getShoppingCart);
router.post("/me/history", protect, checkValidCSRFToken, getMyPurchaseHistory);

export default router;
