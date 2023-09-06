import mongoose from "mongoose";
import { Product } from "../models/productModel.mjs";
import { AppError } from "../utils/appError.mjs";
import { catchAsync } from "../utils/catchAsync.mjs";

const minMongoId = "000000000000";

const filterUpdate = (object) => {
  const filteredObj = {};
  const allowedFields = [
    "name",
    "category",
    "caloriesPerServing",
    "servingsPerOrder",
    "pricePerOrder",
    "imageSrc",
    "imageAlt",
    "description",
    "ingredients",
    "glutenFree",
    "dairyFree",
  ];

  Object.keys(object).forEach((element) => {
    if (allowedFields.includes(element)) filteredObj[element] = object[element];
  });

  return filteredObj;
};

export const getProducts = catchAsync(async (req, res, next) => {
  const products = await Product.find({});

  res.status(200).json({ status: "success", data: { products } });
});

export const getProductNames = catchAsync(async (req, res, next) => {
  const productNames = await Product.find({}).select("name");

  res.status(200).json({ status: "success", data: { productNames } });
});

export const getProduct = catchAsync(async (req, res, next) => {
  const product = await Product.find({ name: req.params.name });

  if (!product)
    return next(new AppError(`No product found for: ${req.param.name}`, 400));

  res.status(200).json({ status: "success", data: { product } });
});

export const getProductsByCategories = catchAsync(async (req, res, next) => {
  let { nextCursor = minMongoId, limit = 10 } = req.params;

  if (isNaN(limit) || !mongoose.isValidObjectId(nextCursor))
    return next(new AppError("Invalid page number and/or cursor value", 400));

  const query = {};
  const allowedCategories = [
    "bread",
    "muffin",
    "cookie",
    "brownie",
    "cake",
    "pie",
    "pastry",
  ];
  const categories = req.params.categories.split(",");
  const categoriesFiltered = [];

  categories.forEach((element) => {
    if (allowedCategories.includes(element)) categoriesFiltered.push(element);
  });

  query.category = { $in: categoriesFiltered };

  if (categories.includes("glutenFree")) query.glutenFree = true;
  if (categories.includes("dairyFree")) query.dairyFree = true;

  const products = await Product.find({
    $and: [query],
    _id: { $gte: nextCursor },
  }).limit(limit + 1);

  nextCursor = products[limit]._id;

  products.length = limit; // alternative to slice(...) -- removing last element

  res
    .status(200)
    .json({ status: "success", data: { nextCursor, limit, products } });
});

export const addNewProduct = catchAsync(async (req, res, next) => {
  const product = await Product.create({
    name: req.body.name,
    category: req.body.category,
    caloriesPerServing: req.body.caloriesPerServing,
    servingsPerOrder: req.body.servingsPerOrder,
    pricePerOrder: req.body.pricePerOrder,
    imageSrc: req.body.imageSrc,
    imageAlt: req.body.imageAlt,
    description: req.body.description,
    ingredients: req.body.ingredients,
    glutenFree: req.body.glutenFree,
    dairyFree: req.body.dairyFree,
  });

  res.status(200).json({ status: "success", data: { product } });
});

export const updateProduct = catchAsync(async (req, res, next) => {
  const filteredObj = filterUpdate(req.body);
  const updatedProduct = await Product.findOneAndUpdate(filteredObj);

  if (!updatedProduct)
    return next(new AppError("Product with that name does not exist.", 400));

  res.status(200).json({ status: "success", data: { updatedProduct } });
});

export const deleteProduct = catchAsync(async (req, res, next) => {
  const deletedProduct = await Product.findOneAndDelete({
    name: req.body.name,
  });

  if (!deletedProduct)
    return next(new AppError("Product with that name does not exist.", 400));

  res.status(200).json({
    status: "success",
    message: "Successfully removed product from database.",
  });
});
