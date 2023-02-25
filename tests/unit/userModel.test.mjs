import { User } from '../../models/userModel.mjs';
import mongoose from 'mongoose';
import { getServer } from '../tempServer.mjs';

describe('User Model', () => {
  let server;
  let expectedUserObjectAfterInsert;
  let validUser;

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

    validUser = {
      name: 'John Doe',
      email: 'johndoe@test.io',
      emailConfirm: 'johndoe@test.io',
      phone: '5555555555',
      password: 'Secret123#',
      passwordConfirm: 'Secret123#',
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

  it('Should reject user when name is missing', async () => {
    delete validUser.name;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when name contains non-alpha character(s)', async () => {
    validUser.name = 'test123';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when email is missing', async () => {
    delete validUser.email;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when email is not a valid email', async () => {
    validUser.email = 'test123';
    validUser.emailConfirm = 'test123';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when emailConfirm is missing', async () => {
    delete validUser.emailConfirm;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when emailConfirm does not match email', async () => {
    validUser.emailConfirm = 'test@test.io';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when phone is missing', async () => {
    delete validUser.phone;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when phone is not a valid phone number (too short)', async () => {
    validUser.phone = '123';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when phone is not a valid phone number (too long)', async () => {
    validUser.phone = '1234567891011';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when password is missing', async () => {
    delete validUser.password;
    delete validUser.passwordConfirm;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when password is not a strong password (0 < points < 10)', async () => {
    validUser.password = 'testing';
    validUser.passwordConfirm = 'testing';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when password is not a strong password (10 <= points < 20)', async () => {
    validUser.password = 'testingtesting';
    validUser.passwordConfirm = 'testingtesting';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when password is not a strong password (20 <= points < 30)', async () => {
    validUser.password = 'Testing';
    validUser.passwordConfirm = 'Testing';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when password is not a strong password (30 <= points < 40)', async () => {
    validUser.password = 'Testing1';
    validUser.passwordConfirm = 'Testing1';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when passwordConfirm is missing', async () => {
    delete validUser.passwordConfirm;
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });

  it('Should reject user when passwordConfirm does not match password', async () => {
    validUser.passwordConfirm = 'unmatchedPassword';
    const user = new User(validUser);
    await expect(user.save()).rejects.toThrow(mongoose.Error.ValidationError);
  });
});
