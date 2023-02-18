import mongoose from 'mongoose';
import validator from 'validator';

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: true,
    minLength: 5,
    maxLength: 50,
    validate: {
      validator: function (value) {
        return validator.isAlpha(value.replace(/\s/g, ''));
      },
    },
  },
  category: {
    type: String,
    enum: ['bread', 'muffin', 'cookie', 'brownie', 'cake', 'pie', 'pastry'],
    required: [true, 'Product must have a category'],
  },
  quantityPerOrder: { type: Number, required: true, min: 1 },
  price: { type: Number, required: [true, 'Product must have a price.'] },
  subscriberPrice: {
    type: Number,
    default: this.price * 0.8,
    validate: {
      validator: function (value) {
        return value > 0 && value < this.price;
      },
    },
  },
  image: { type: String, required: [true, 'Product must have an associated image.'] },
  description: { type: String, maxLength: 250, trim: true, required: [true, 'Product must have a description.'] },
  ingredients: { type: [String], required: [true, 'Product must contain ingredients.'] },
  glutenFree: { type: Boolean, default: false },
  dairyFree: { type: Boolean, default: false },
});

export const Product = mongoose.model('Product', productSchema);
