import mongoose from "mongoose";
import { Order } from "../models/orderModel.mjs";
import { Product } from "../models/productModel.mjs";
import { AppError } from "../utils/appError.mjs";
import { catchAsync } from "../utils/catchAsync.mjs";
import validator from "validator";
import { products } from "../server.mjs";

const validateName = (name) => validator.isAlphanumeric(name.replaceAll(/[\s-]/g, ""));
const validatePhone = (phone) => /^\(?(\d{3})\)?[- ]?(\d{3})(\ -\ )?(\d{4})$/.test(phone);
const validateZip = (zip) => /(^\d{5}$)|(^\d{5}(\ -\ )\d{4}$)/.test(zip);

export const submitOrderUser = catchAsync(async (req, res, next) => {
  setTimeout(async () => {
    const { orderNumber, orderName, phone, zip } = req.body;

    if (!orderNumber || !orderName || !phone)
      return next(new AppError("Missing one or more of the following: order number, order name, phone number.", 400));

    const nameIsValid = validateName(orderName);
    const phoneIsValid = validatePhone(phone);
    const zipIsValid = zip ? validateZip(zip) : undefined;

    if (zip && (!nameIsValid || !phoneIsValid || !zipIsValid))
      return next(new AppError("One or more of the following is/are invalid: name, phone, zip.", 400));

    if (!zip && (!nameIsValid || !phoneIsValid))
      return next(new AppError("One or more of the following is/are invalid: name, phone.", 400));

    let submittedOrder = await Order.findByIdAndUpdate(
      req.body.orderNumber,
      {
        orderSubmitted: true,
      },
      { new: true }
    );

    if (!submittedOrder)
      return next(
        new AppError("Sorry we could not find your order (invalid order Id). Please log in again and retry.", 400)
      );

    if (!req.user._id.equals(submittedOrder.user))
      return next(new AppError("Order does not belong to account. Please log back in and try again.", 400));

    const subtotal = +submittedOrder.products
      .reduce((accumulator, product) => {
        const matchingProduct = products.find((item) => item._id.equals(product._id));
        return accumulator + matchingProduct.pricePerOrder * product.quantity;
      }, 0)
      .toFixed(2);

    const taxes = +(subtotal * 0.08).toFixed(2);

    const purchasePrice = +(subtotal + taxes).toFixed(2);

    submittedOrder.subtotal = subtotal;
    submittedOrder.taxes = taxes;
    submittedOrder.purchasePrice = purchasePrice;
    await submittedOrder.save();

    res.status(200).json({ status: "success", data: { submittedOrder } });
  }, 2500);
});

export const submitOrderGuest = catchAsync(async (req, res, next) => {
  setTimeout(async () => {
    const { orderedProducts, orderName, phone, zip } = req.body;

    if (!products || !orderName || !phone)
      return next(new AppError("Missing one or more of the following: products, order name, phone number.", 400));

    const nameIsValid = validateName(orderName);
    const phoneIsValid = validatePhone(phone);
    const zipIsValid = zip ? validateZip(zip) : undefined;

    if (zip && (!nameIsValid || !phoneIsValid || !zipIsValid))
      return next(new AppError("One or more of the following is/are invalid: name, phone, zip.", 400));

    if (!zip && (!nameIsValid || !phoneIsValid))
      return next(new AppError("One or more of the following is/are invalid: name, phone.", 400));

    const subtotal = +orderedProducts
      .reduce((accumulator, product) => {
        const matchingProduct = products.find((item) => item._id.equals(product._id));
        console.log(matchingProduct);
        return accumulator + matchingProduct.pricePerOrder * product.quantity;
      }, 0)
      .toFixed(2);

    console.log(typeof subtotal);

    const taxes = +(subtotal * 0.08).toFixed(2);

    const purchasePrice = +(subtotal + taxes).toFixed(2);

    const submittedOrder = await Order.create({
      orderSubmitted: true,
      orderPaid: zip ? true : false,
      orderName: orderName,
      phoneNumber: phone,
      products: orderedProducts,
      purchaseDate: new Date(),
      subtotal: subtotal,
      taxes: taxes,
      purchasePrice: purchasePrice,
    });

    res.status(200).json({ status: "success", data: { submittedOrder } });
  }, 2500);
});

export const updateShoppingCart = catchAsync(async (req, res, next) => {
  const allQuantitiesWithinLimit = req.body.products.every(
    (product) => product.quantity <= +process.env.MAX_ORDER_QUANTITY
  );

  if (!allQuantitiesWithinLimit)
    return next(new AppError(`One or more product quantities exceeds limit ${process.env.MAX_ORDER_QUANTITY}.`, 400));

  let shoppingCart = await Order.findOneAndUpdate(
    {
      user: req.user._id,
      orderSubmitted: false,
    },
    { products: req.body.products },
    { runValidators: true, new: true }
  );

  if (!shoppingCart)
    return next(new AppError("Unable to update shopping cart. Please log out and log back in if issue persists.", 400));

  res.status(200).json({ status: "success", message: "Cart updated successfully." });
});

export const getMyPurchaseHistory = catchAsync(async (req, res, next) => {
  const purchaseHistory = await Order.find({
    user: req.user._id,
    orderSubmitted: true,
  });

  res.status(200).json({ status: "success", data: { purchaseHistory } });
});

export const getShoppingCart = catchAsync(async (req, res) => {
  let shoppingCart = await Order.findOne({
    user: req.user._id,
    orderSubmitted: false,
  });

  if (!shoppingCart) shoppingCart = await Order.create({ user: req.user._id });

  const { _id, products } = shoppingCart;

  res.status(200).json({ status: "success", cart: { _id, products } });
});
