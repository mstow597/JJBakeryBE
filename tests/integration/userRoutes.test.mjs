import supertest from 'supertest';
import mongoose from 'mongoose';
import { getServer } from '../tempServer.mjs';
import { User } from '../../models/userModel.mjs';

describe('Routes - /api/v1/users', () => {
  describe('Signup', () => {
    let server;
    let existingUser;
    let validUser;

    const expectedSuccessResponseObject = {
      status: 'success',
      message:
        `You're account was successfully created. Prior to accessing you account, you must verify your email address with the link provided in a message sent to your email address` +
        '(NODE_ENV test only)',
    };

    const expectedUser = {
      name: 'testing testing',
      email: 'testing1@test.io',
      phone: '5555555555',
      role: 'user',
      verified: false,
      active: true,
      __v: 0,
    };

    beforeEach(async () => {
      server = await getServer();

      existingUser = {
        name: 'testing test',
        email: 'testing5@test.io',
        emailConfirm: 'testing5@test.io',
        phone: '5555555555',
        password: 'Testing1234!@',
        passwordConfirm: 'Testing1234!@',
      };

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      await User.create(existingUser);
    });
    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should reject user signup when desired email already in use by an account in database', async () => {
      const res = await supertest(server).post('/api/v1/users/signup').send(existingUser);

      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({
        status: 'failed',
        message: `Sorry we were unable to create your account. If you are unsure if an account exists for the requested email address, consider submitting a password reset or email verification request.`,
      });
    });

    it('should create a new user successfully (no duplicate key)', async () => {
      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const user = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(201);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when role data field is passed', async () => {
      validUser.role = 'admin';

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.role).toMatch('user');
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when passwordChangedAt data field is passed', async () => {
      validUser.passwordChangedAt = Date.now();

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.passwordChangedAt).not.toBeDefined();
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when passwordResetToken data field is passed', async () => {
      validUser.passwordResetToken = '12345';

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.passwordResetToken).not.toBeDefined();
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when passwordResetExpires data field is passed', async () => {
      validUser.passwordResetExpires = Date.now();

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.passwordResetExpires).not.toBeDefined();
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when emailVerificationToken data field is passed', async () => {
      validUser.emailVerificationToken = '12345';

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.emailVerificationToken).not.toMatch('12345');
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when emailVerificationTokenExpires data field is passed', async () => {
      const incorrectTime = Date.now() - 1000;
      validUser.emailVerificationTokenExpires = incorrectTime;

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(Number(user.emailVerificationTokenExpires)).not.toEqual(Number(incorrectTime));
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when csrftoken data field is passed', async () => {
      validUser.csrfToken = '12345';

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.csrfToken).not.toBeDefined();
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when csrfTokenExpires data field is passed', async () => {
      const incorrectTime = Date.now() - 1000;
      validUser.csrfTokenExpires = incorrectTime;

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(Number(user.csrfTokenExpires)).not.toEqual(Number(incorrectTime));
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when verified data field is passed', async () => {
      validUser.verified = true;

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.verified).toBe(false);
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });

    it('Should insert validated user and ignore/override when active data field is passed', async () => {
      validUser.active = false;

      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const user = await User.findOne({ email: validUser.email });

      expect(user.active).toBe(true);
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject(expectedSuccessResponseObject);
      expect(user._id).toBeDefined();
      expect(user.emailVerificationToken).toBeDefined();
      expect(user.emailVerificationTokenExpires).toBeDefined();
      expect(user).toMatchObject(expectedUser);
    });
  });

  describe('Login', () => {
    let verifiedUser, nonVerifiedUser, server;

    const verifiedUserData = {
      name: 'testing test',
      email: 'testing5@test.io',
      emailConfirm: 'testing5@test.io',
      phone: '5555555555',
      password: 'Testing1234!@',
      passwordConfirm: 'Testing1234!@',
    };

    const nonVerifiedUserData = {
      name: 'testing testing',
      email: 'testing1@test.io',
      emailConfirm: 'testing1@test.io',
      phone: '5555555555',
      password: 'Testing1234!@#',
      passwordConfirm: 'Testing1234!@#',
    };

    beforeEach(async () => {
      server = await getServer();

      const res = await supertest(server).post('/api/v1/users/signup').send(verifiedUserData);
      await supertest(server).post('/api/v1/users/signup').send(nonVerifiedUserData);

      verifiedUser = await User.findOne({ email: verifiedUserData.email });
      nonVerifiedUser = await User.findOne({ email: nonVerifiedUserData.email });

      const emailToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${emailToken}`);

      verifiedUser = await User.findOne({ email: verifiedUserData.email });
      nonVerifiedUser = await User.findOne({ email: nonVerifiedUserData.email });
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully complete login for verified user and send csrfToken + JWT in response', async () => {
      const res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: verifiedUserData.email, password: verifiedUserData.password });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      cookies.forEach((element) => {
        const array = element.split(/=/);
        cookiesObj[array[0]] = array.slice(1).join('=');
      });

      expect(res.status).toBe(200);
      expect(cookiesObj.jwt).toBeDefined();
      expect(cookiesObj.csrf).toBeDefined();
    });

    it('should reject login for non-verified user (i.e. do not send JWT and csrf token)', async () => {
      const res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: nonVerifiedUserData.email, password: nonVerifiedUserData.password });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
        });
        expect(cookiesObj.jwt).not.toBeDefined();
        expect(cookiesObj.csrf).not.toBeDefined();
      }

      expect(res.status).toBe(401);
    });
  });

  describe('Forgot Password', () => {
    let validUser, server;

    const validUserData = {
      name: 'testing test',
      email: 'testing5@test.io',
      emailConfirm: 'testing5@test.io',
      phone: '5555555555',
      password: 'Testing1234!@',
      passwordConfirm: 'Testing1234!@',
    };

    beforeEach(async () => {
      server = await getServer();

      await supertest(server).post('/api/v1/users/signup').send(validUserData);

      validUser = await User.findOne({ email: validUserData.email });
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully generate and send email when account with req.body.email exists', async () => {
      const res = await supertest(server).post('/api/v1/users/forgotPassword').send({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch('Link sent to email!(NODE_ENV test only)');
    });

    it('should fail but fake sending message if req.body.email is not associated with an account', async () => {
      const res = await supertest(server)
        .post('/api/v1/users/forgotPassword')
        .send({ email: 'nonexistentEmail@test.io' });

      expect(res.status).toBe(200);
      expect(res.body.token).not.toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch('Faking link sent to email - not truly sent');
    });

    it('should fail but fake sending message if req.body.email is missing', async () => {
      const res = await supertest(server).post('/api/v1/users/forgotPassword').send();

      expect(res.status).toBe(200);
      expect(res.body.token).not.toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch('Faking link sent to email - not truly sent');
    });
  });

  describe('Reset Password (GET)', () => {
    let validUser, server;

    const validUserData = {
      name: 'testing test',
      email: 'testing5@test.io',
      emailConfirm: 'testing5@test.io',
      phone: '5555555555',
      password: 'Testing1234!@',
      passwordConfirm: 'Testing1234!@',
    };

    beforeEach(async () => {
      server = await getServer();

      await supertest(server).post('/api/v1/users/signup').send(validUserData);

      validUser = await User.findOne({ email: validUserData.email });
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully complete request when token is valid', async () => {
      let res = await supertest(server).post('/api/v1/users/forgotPassword').send({ email: validUser.email });
      const token = res.body.token;
      res = await supertest(server).get(`/api/v1/users/resetPassword/${token}`);

      expect(res.status).toBe(200);
    });
    it('should reject request when token is invalid', async () => {
      const res = await supertest(server).get(`/api/v1/users/resetPassword/invalidToken`);

      expect(res.status).toBe(400);
    });
    it('should reject request when token is expired', async () => {
      const actualTokenExpiration = process.env.TOKEN_EXPIRATION;
      process.env.TOKEN_EXPIRATION = 0;

      let res = await supertest(server).post('/api/v1/users/forgotPassword').send({ email: validUser.email });
      const token = res.body.token;

      process.env.TOKEN_EXPIRATION = actualTokenExpiration;

      res = await supertest(server).get(`/api/v1/users/resetPassword/${token}`);
      expect(res.status).toBe(400);
    });
  });

  describe('Reset Password (POST)', () => {
    let validUser, token, server;

    const validUserData = {
      name: 'testing test',
      email: 'testing5@test.io',
      emailConfirm: 'testing5@test.io',
      phone: '5555555555',
      password: 'Testing1234!@',
      passwordConfirm: 'Testing1234!@',
    };

    beforeEach(async () => {
      server = await getServer();

      let res = await supertest(server).post('/api/v1/users/signup').send(validUserData);

      validUser = await User.findOne({ email: validUserData.email }).select('+password');

      res = await supertest(server).post('/api/v1/users/forgotPassword').send({ email: validUserData.email });
      token = res.body.token;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully reset password when all conditions met: token valid and not expired, strong password, passwordConfirm === password', async () => {
      const res = await supertest(server)
        .post(`/api/v1/users/resetPassword/${token}`)
        .send({ password: 'UpdatedPass12!@', passwordConfirm: 'UpdatedPass12!@' });

      const oldPassword = validUser.password;
      validUser = await User.findById(validUser._id).select('+password');
      expect(res.status).toBe(200);
      expect(oldPassword).not.toMatch(validUser.password);
    });

    it('should reject password reset when token is invalid', async () => {
      const res = await supertest(server)
        .post(`/api/v1/users/resetPassword/invalidToken`)
        .send({ password: 'UpdatedPass12!@', passwordConfirm: 'UpdatedPass12!@' });

      expect(res.status).toBe(400);
    });

    it('should reject password reset when token is expired', async () => {
      const actualTokenExpiration = process.env.TOKEN_EXPIRATION;
      process.env.TOKEN_EXPIRATION = 0;

      let res = await supertest(server).post('/api/v1/users/forgotPassword').send({ email: validUser.email });
      const token = res.body.token;

      process.env.TOKEN_EXPIRATION = actualTokenExpiration;

      res = await supertest(server)
        .post(`/api/v1/users/resetPassword/${token}`)
        .send({ password: 'UpdatedPass12!@', passwordConfirm: 'UpdatedPass12!@' });

      expect(res.status).toBe(400);
    });
    it('should reject password reset when req.password missing', async () => {});
    it('should reject password reset when req.passwordConfirm missing', async () => {});
    it('should reject password reset when req.password not validated (not strong enough)', async () => {});
  });

  describe('Send Email Verification', () => {});

  describe('Verify Email', () => {});

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.disconnect();
  });
});
