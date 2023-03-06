import mongoose from 'mongoose';

/**
 * @description
 * - Holds transaction data for current (transactionComplete === false) and all prior transactions
 * - A user should have only 1 transaction with transactionComplete = false (acts as a current shopping cart)
 * - On opening web application as logged in user, query DB for order with transactionComplete === false and send to user to store in localStorage
 * - If not logged in and ordering as a guest, all order data stored in localStorage until transaction complete ()
 */
const orderSchema = new mongoose.Schema({
  transactionComplete: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: undefined },
  price: { type: Number, default: 0, min: 0 },
  products: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
      quantity: {
        type: Number,
        required: [true, 'Must provide how many orders you wish to purchase of this product'],
        min: 1,
        validate: {
          validator: function (value) {
            return value % 0.5 === 0;
          },
          message: 'Quantity must be a multiple of 0.5 (one-half).',
        },
      },
    },
  ],
});

export const Order = mongoose.model('Order', orderSchema);
