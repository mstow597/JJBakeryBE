import mongoose from "mongoose";

/**
 * @description
 * - Holds transaction data for current (orderSubmitted === false) and all prior transactions
 * - A user should have only 1 transaction with orderSubmitted = false (acts as a current shopping cart)
 * - On opening web application as logged in user, query DB for order with orderSubmitted === false and send to app
 * - If not logged in and ordering as a guest, all order data stored in localStorage until transaction complete
 */
const orderSchema = new mongoose.Schema({
  orderSubmitted: { type: Boolean, default: false },
  orderPaid: { type: Boolean, default: false },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: undefined,
  },
  orderName: {
    type: String,
    require: [true, "Must provide a name for the order."],
  },
  phoneNumber: {
    type: String,
    require: [true, "Must provide a phone number for the order."],
  },
  subtotal: { type: Number, default: 0, min: 0 },
  taxes: { type: Number, default: 0, min: 0 },
  purchasePrice: { type: Number, default: 0, min: 0 },
  purchaseDate: { type: Date, default: undefined },
  products: {
    default: [],
    type: [
      {
        _id: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
          required: [true, "Product invalid or not specified."],
        },
        quantity: {
          type: Number,
          required: [true, "Must provide how many orders you wish to purchase of this product (min = 1, max = 10)"],
          min: 1,
          max: 10,
        },
      },
    ],
  },
});

export const Order = mongoose.model("Order", orderSchema);
