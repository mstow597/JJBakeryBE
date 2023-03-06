import mongoose from 'mongoose';
import { Product } from '../models/productModel.mjs';
import { AppError } from '../utils/appError.mjs';
import { catchAsync } from '../utils/catchAsync.mjs';

const minMongoId = '000000000000';

export const getProducts = catchAsync(async (req, res, next) => {
  let { nextCursor = minMongoId, limit = 10 } = req.params;

  if (isNaN(limit) || !mongoose.isValidObjectId(nextCursor))
    return next(new AppError('Invalid page number and/or cursor value', 400));

  const products = await Product.find({ _id: { $gte: nextCursor } }).limit(limit + 1);
  nextCursor = products[limit]._id;

  products.length = limit; // alternative to slice(...) -- removing last element
  res.status(200).json({ status: 'success', data: { nextCursor, limit, products } });
});

export const getProductNames = catchAsync(async (req, res, next) => {
  const productNames = await Product.find({}).select('name');

  res.status(200).json({ status: 'success', data: { productNames } });
});

export const getProduct = catchAsync(async (req, res, next) => {
  const product = await Product.find({ name: req.params.name });

  if (!product) return next(new AppError(`No product found for: ${req.param.name}`, 400));

  res.status(200).json({ status: 'success', data: { product } });
});

export const getProductsByCategories = catchAsync(async (req, res, next) => {
  let { nextCursor = minMongoId, limit = 10 } = req.params;

  if (isNaN(limit) || !mongoose.isValidObjectId(nextCursor))
    return next(new AppError('Invalid page number and/or cursor value', 400));

  const query = {};
  const allowedCategories = ['bread', 'muffin', 'cookie', 'brownie', 'cake', 'pie', 'pastry'];
  const categories = req.params.categories.split(',');
  const categoriesFiltered = [];

  categories.forEach((element) => {
    if (allowedCategories.includes(element)) categoriesFiltered.push(element);
  });

  query.category = { $in: categoriesFiltered };

  if (categories.includes('glutenFree')) query.glutenFree = true;
  if (categories.includes('dairyFree')) query.dairyFree = true;

  const products = await Product.find({ $and: [query], _id: { $gte: nextCursor } }).limit(limit + 1);

  nextCursor = products[limit]._id;

  products.length = limit; // alternative to slice(...) -- removing last element

  res.status(200).json({ status: 'success', data: { nextCursor, limit, products } });
});

export const addNewProduct = catchAsync((req, res, next) => {});
export const updateProduct = catchAsync((req, res, next) => {});
export const deleteProduct = catchAsync((req, res, next) => {});
