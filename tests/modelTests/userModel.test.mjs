import mongoose from 'mongoose';
import { User } from '../../models/userModel.mjs';
import { sum } from './sum.mjs';

test('adds 1 + 2 to equal 3', () => {
  expect(sum(1, 2)).toBe(3);
});
