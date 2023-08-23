import '../config.mjs';
import app from '../app.mjs';
import mongoose from 'mongoose';

export const getServer = async () => {
  const DB = process.env.DATABASE_TEST.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

  await mongoose.connect(DB);

  const port = process.env.PORT || 3000;
  const server = app.listen(port, '127.0.0.1');

  return server;
};
