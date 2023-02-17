import mongoose from 'mongoose';
import validator from 'validator';

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: true,
    validate: {
      validator: function (value) {
        return validator.isAlpha(value.replace(/\s/g, ''));
      },
    },
  },
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
  description: { type: String, maxLength: 250, trim: true, required: [true, 'Product must have a description.'] },
  ingredients: [String],
  ratingsAverage: { type: Number, default: 3, min: 1, max: 5 },
  ratingsQuantity: { type: Number, default: 0 },
});

export const Product = mongoose.model('Product', productSchema);
