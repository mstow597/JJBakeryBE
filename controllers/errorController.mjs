import { AppError } from '../utils/appError.mjs';

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  return new AppError(err.message, 400);
};

const handleValidationErrorDB = (err) => {
  return new AppError(err.message, 400);
};

const handleJWTError = () => {
  return new AppError('Invalid token. Please log in again!', 401);
};

const handleJWTExpiredError = () => {
  return new AppError('Your token has expired. Please log in again.', 401);
};

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({ status: err.status, error: err, message: err.message, stack: err.stack });
};

const sendErrorProd = (err, res) => {
  // Operational trusted error: send message to the client
  if (err.isOperational) res.status(err.statusCode).json({ status: err.status, message: err.message });
  // Programming or other unknown error: don't leak details to client.
  else {
    // Log error for our own purposes
    console.error('ERROR', err.stack);
    // Send generic message to client.
    res.status(500).json({ status: 'error', message: 'Something went very wrong.' });
  }
};

export default function (err, req, res, next) {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') sendErrorDev(err, res);
  else if (process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test') {
    let error = err;
    if (err.name === 'CastError') error = handleCastErrorDB(err);
    if (err.code === 11000) error = handleDuplicateFieldsDB(err);
    if (err.name === 'ValidationError') error = handleValidationErrorDB(err);
    if (err.name === 'JsonWebTokenError') error = handleJWTError();
    if (err.name === 'TokenExpiredError') error = handleJWTExpiredError();
    sendErrorProd(error, res);
  }
}
