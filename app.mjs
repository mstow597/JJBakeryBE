import express from "express";
import morgan from "morgan";
import helmet from "helmet";
import xss from "xss-clean";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import globalErrorHandler from "./controllers/errorController.mjs";
import userRouter from "./routes/userRouter.mjs";
import productRouter from "./routes/productRouter.mjs";
import orderRouter from "./routes/orderRouter.mjs";
import { AppError } from "./utils/appError.mjs";
import cookieParser from "cookie-parser";
import cors from "cors";

const limiter = rateLimit({
  windowMS: 10 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later!",
});

const corsOptions = {
  origin: "http://localhost:1234", // Replace with the origin of your React app
  methods: "GET, POST, PATCH, DELETE, OPTIONS", // Specify the allowed HTTP methods
  allowedHeaders: "Content-Type, Authorization", // Specify the allowed headers
  credentials: true,
};

const app = express();

if (process.env.NODE_ENV === "development") app.use(morgan("dev")); // development logging
if (process.env.NODE_ENV !== "test") app.use("/api", limiter);

app.use(cors(corsOptions));
app.use(express.static(`./public`));
app.use(cookieParser());
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp({ whitelist: [""] }));
app.use("/api/v1/users", userRouter);
app.use("/api/v1/products", productRouter);
app.use("/api/v1/orders", orderRouter);
app.use("*", (req, res, next) =>
  next(new AppError(`Can't find ${req.originalUrl}`, 404)),
);
app.use(globalErrorHandler);

export default app;
