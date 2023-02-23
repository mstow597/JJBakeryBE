import supertest from 'supertest';
import mongoose from 'mongoose';
import { getServer } from '../tempServer.mjs';
import { User } from '../../models/userModel.mjs';

describe('Routes - /api/v1/users', () => {
  describe('Signup', () => {
    let server;
    let existingUser = {
      name: 'testing test',
      email: 'testing5@test.io',
      emailConfirm: 'testing5@test.io',
      phone: '5555555555',
      password: 'Testing1234!@',
      passwordConfirm: 'Testing1234!@',
    };
    beforeEach(async () => {
      server = await getServer();
      await User.create(existingUser);
    });
    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });
    it('should create a new user successfully (no duplicate key)', async () => {
      const user = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      const expectedResponseObject = {
        status: 'success',
        message:
          `You're account was successfully created. Prior to accessing you account, you must verify your email address with the link provided in a message sent to your email address` +
          '(NODE_ENV test only)',
      };
      const res = await supertest(server).post('/api/v1/users/signup').send(user);
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedResponseObject);
    });

    it('should reject user signup when desired email already in use by an account in database', async () => {
      const res = await supertest(server).post('/api/v1/users/signup').send(existingUser);
      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({
        status: 'failed',
        message: `Sorry we were unable to create your account. If you are unsure if an account exists for the requested email address, consider submitting a password reset or email verification request.`,
      });
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
  });
  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.disconnect();
  });
});
