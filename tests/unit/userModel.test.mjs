import { User } from '../../models/userModel.mjs';
import mongoose from 'mongoose';
import { getServer } from '../tempServer.mjs';

describe('User Model', () => {
  let server;
  let expectedUserObjectAfterInsert;
  const validUser = {
    name: 'John Doe',
    email: 'johndoe@test.io',
    emailConfirm: 'johndoe@test.io',
    phone: '5555555555',
    password: 'Secret123#',
    passwordConfirm: 'Secret123#',
  };

  const handleHashAndPreSave = (userAfterSave) => {
    expectedUserObjectAfterInsert.passwordConfirm = undefined;
    expectedUserObjectAfterInsert.password = userAfterSave.password;
    expectedUserObjectAfterInsert._id = userAfterSave._id;
    expectedUserObjectAfterInsert.__v = userAfterSave.__v;
  };

  beforeEach(async () => {
    server = await getServer();
    expectedUserObjectAfterInsert = {
      name: 'John Doe',
      email: 'johndoe@test.io',
      emailConfirm: 'johndoe@test.io',
      phone: '5555555555',
      password: 'Secret123#',
      passwordConfirm: 'Secret123#',
      role: 'user',
      verified: false,
      active: true,
    };
  });

  afterEach(async () => {
    await User.deleteMany({});
    await server.close();
  });

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.disconnect();
    await server.close();
  });

  it('Should insert new user when all validation checks pass', async () => {
    const user = new User(validUser);
    await expect(user.save()).resolves.toBeTruthy();
  });
  it('Should match expected object when validated user and no additional fields passed', async () => {
    const user = new User(validUser);
    const userAfterSave = await user.save();
    handleHashAndPreSave(userAfterSave);
    expect(userAfterSave).toMatchObject(expectedUserObjectAfterInsert);
  });
  it('Should insert validated user and ignore/override when role data field is passed', async () => {});
  it('Should insert validated user and ignore/override when passwordChangedAt data field is passed', async () => {});
  it('Should insert validated user and ignore/override when passwordResetToken data field is passed', async () => {});
  it('Should insert validated user and ignore/override when passwordResetExpires data field is passed', async () => {});
  it('Should insert validated user and ignore/override when emailVerificationToken data field is passed', async () => {});
  it('Should insert validated user and ignore/override when csrftoken data field is passed', async () => {});
  it('Should insert validated user and ignore/override when csrfTokenExpires data field is passed', async () => {});
  it('Should insert validated user and ignore/override when verified data field is passed', async () => {});
  it('Should insert validated user and ignore/override when active data field is passed', async () => {});
  it('Should reject user when name is missing', async () => {});
  it('Should reject user when name contains non-alpha character(s)', async () => {});
  it('Should reject user when email is missing', async () => {});
  it('Should reject user when email is not a valid email', async () => {});
  it('Should reject user when emailConfirm is missing', async () => {});
  it('Should reject user when emailConfirm does not match email', async () => {});
  it('Should reject user when phone is missing', async () => {});
  it('Should reject user when phone is not a valid phone number', async () => {});
  it('Should reject user when password is missing', async () => {});
  it('Should reject user when password is not a strong password (0 < points < 10)', async () => {});
  it('Should reject user when password is not a strong password (10 <= points < 20)', async () => {});
  it('Should reject user when password is not a strong password (20 <= points < 30)', async () => {});
  it('Should reject user when password is not a strong password (30 <= points < 40)', async () => {});
  it('Should reject user when passwordConfirm is missing', async () => {});
  it('Should reject user when passwordConfirm does not match password', async () => {});
});
