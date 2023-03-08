import mongoose from 'mongoose';
import { Order } from '../models/orderModel.mjs';
import { Product } from '../models/productModel.mjs';
import { AppError } from '../utils/appError.mjs';
import { catchAsync } from '../utils/catchAsync.mjs';

export const submitOrder = catchAsync(async (req, res, next) => {
  const submittedOrder = await Order.findByIdAndUpdate(req.body.orderNumber, { transactionComplete: true });

  if (!submittedOrder)
    return next(new AppError('Unable to complete transaction. If issue persists, please log out and in.', 400));

  res.status(200).json({ status: 'success', data: { submittedOrder } });
});
export const updateShoppingCart = catchAsync(async (req, res, next) => {
  // Note: using findByIdAndUpdate strictly to validate input of products array.
  // Want to be sure products are of type Product that exists in DB and quantity within validation restrictions.
  // Otherwise, could simply use findById()
  let shoppingCart = await Order.findByIdAndUpdate(
    req.body.orderNumber,
    { products: req.body.products },
    { runValidators: true, new: true }
  );

  if (!shoppingCart)
    return next(new AppError('Unable to update shopping cart. Please log out and log back in if issue persists.', 400));

  const consolidatedDuplicatedObj = {};
  shoppingCart.products.forEach((element) => {
    if (!consolidatedDuplicatedObj[element.product]) consolidatedDuplicatedObj[element.product] = element.quantity;
    else consolidatedDuplicatedObj[element.product] = consolidatedDuplicatedObj[element.product] + element.quantity;
  });

  shoppingCart.products = [];
  for (const [key, value] of Object.entries(consolidatedDuplicatedObj))
    shoppingCart.products.push({ product: key, quantity: value });

  let productsInShoppingcart = [];
  shoppingCart.products.forEach((element) => productsInShoppingcart.push(Product.findById(element.product)));
  productsInShoppingcart = await Promise.all(productsInShoppingcart);

  const productsInShoppingcartObj = {};
  productsInShoppingcart.forEach((element) => (productsInShoppingcartObj[element._id] = element));

  shoppingCart.purchasePrice = 0;
  shoppingCart.products.forEach((element) => {
    shoppingCart.purchasePrice += productsInShoppingcartObj[element.product].pricePerOrder * element.quantity;
  });

  shoppingCart = await shoppingCart.save();

  res.status(200).json({ status: 'success', data: { shoppingCart } });
});
export const getMyPurchaseHistory = catchAsync(async (req, res, next) => {
  const purchaseHistory = await Order.find({ user: req.user._id, transactionComplete: true });

  res.status(200).json({ status: 'success', data: { purchaseHistory } });
});
export const getShoppingCart = catchAsync(async (req, res, next) => {
  let shoppingCart = await Order.findOne({ user: req.user._id, transactionComplete: false });

  if (!shoppingCart) shoppingCart = await Order.create({ user: req.user._id });

  res.status(200).json({ status: 'success', data: { shoppingCart } });
});
