import mongoose from 'mongoose';
import validator from 'validator';

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: true,
    lowercase: true,
    unique: true,
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
    lowercase: true,
    required: [true, 'Product must have a category'],
    enum: ['bread', 'muffin', 'cookie', 'brownie', 'cake', 'pie', 'pastry'],
  },
  caloriesPerServing: { type: Number, required: [true, 'Product must have a value for calories per serving.'] },
  servingsPerOrder: { type: Number, required: [true, 'Product must have a quantity per order.'], min: 1 },
  pricePerOrder: { type: Number, required: [true, 'Product must have a price per order.'], min: 0 },
  imageSrc: { type: String, required: [true, 'Product must have an associated image.'] },
  imageAlt: { type: String, required: [true, 'Product must have an alt description for the image.'] },
  description: { type: String, maxLength: 250, trim: true, required: [true, 'Product must have a description.'] },
  ingredients: {
    type: [String],
    required: [true, 'Product must contain one or more ingredients.'],
    validate: {
      validator: function (value) {
        return value.every((element) => validator.isAlpha(element.replace(/\s/g, '')));
      },
      message: 'All ingredients must contain only alpha characters.',
    },
  },
  glutenFree: { type: Boolean, default: false },
  dairyFree: { type: Boolean, default: false },
});

export const Product = mongoose.model('Product', productSchema);
