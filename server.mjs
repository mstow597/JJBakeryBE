import "./config.mjs";
import app from "./app.mjs";
import mongoose from "mongoose";
import { Product } from "./models/productModel.mjs";

process.on("uncaughtException", (err) => {
  console.log(err.name, err);
  console.log("UNHANDLED EXCEPTION! 🔴 Shutting Down...");
  server.close(() => {
    process.exit(1);
  });
});

process.on("unhandledRejection", (err) => {
  console.log(err.name, err);
  console.log("UNHANDLED REJECTION! 🔴 Shutting Down...");
  server.close(() => {
    process.exit(1);
  });
});

const DB = process.env.DATABASE.replace("<PASSWORD>", process.env.DATABASE_PASSWORD);

await mongoose.connect(DB).then((conn) => {
  console.log("DB connection successful!");
});

export const products = await Product.find({});
const port = process.env.PORT || 3000;
const server = app.listen(port, "127.0.0.1", () => console.log(`Listening on port ${port}...`));
