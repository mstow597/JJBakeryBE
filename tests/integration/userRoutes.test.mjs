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
        'An email has been sent to the provided email address with instructions on how to proceed with account setup/updating.(NODE_ENV test only)',
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

      expect(res.status).toBe(200);
    });

    it('should create a new user successfully (no duplicate key)', async () => {
      console.log(validUser);
      const res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      console.log(res);

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
    let verifiedUser, server;

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

      const emailToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${emailToken}`);
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

      expect(res.status).toBe(400);
    });

    it('should reject login when email is missing', async () => {
      const res = await supertest(server).post('/api/v1/users/login').send({ password: verifiedUserData.password });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
        });
      }

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch('Missing email or password');
      expect(cookiesObj.jwt).not.toBeDefined();
      expect(cookiesObj.csrf).not.toBeDefined();
    });

    it('should reject login when password is missing', async () => {
      const res = await supertest(server).post('/api/v1/users/login').send({ email: verifiedUserData.email });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
        });
      }

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch('Missing email or password');
      expect(cookiesObj.jwt).not.toBeDefined();
      expect(cookiesObj.csrf).not.toBeDefined();
    });

    it('should reject login when password is incorrect', async () => {
      const res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: verifiedUserData.email, password: 'incorrectPassword' });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
        });
      }

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(
        'Incorrect email or password, email not verified (must be verified to access account), account inactived (to reactivate, please contact customer service using our contact form), or account does not exist.'
      );
      expect(cookiesObj.jwt).not.toBeDefined();
      expect(cookiesObj.csrf).not.toBeDefined();
    });

    it('should reject login when user active status set to false', async () => {
      verifiedUser = await User.findOne({ email: verifiedUserData.email });

      await verifiedUser.setActiveFalse();
      const res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: verifiedUserData.email, password: nonVerifiedUserData.password });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
        });
      }

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(
        'Incorrect email or password, email not verified (must be verified to access account), account inactived (to reactivate, please contact customer service using our contact form), or account does not exist.'
      );
      expect(cookiesObj.jwt).not.toBeDefined();
      expect(cookiesObj.csrf).not.toBeDefined();
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
      expect(res.body.message).toMatch(process.env.DUPLICATE_EMAIL_MESSAGE);
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

    it('should reject password reset when req.password missing', async () => {
      const res = await supertest(server)
        .post(`/api/v1/users/resetPassword/${token}`)
        .send({ passwordConfirm: 'UpdatedPass12!@' });

      const oldPassword = validUser.password;
      validUser = await User.findById(validUser._id).select('+password');

      expect(res.status).toBe(401);
      expect(oldPassword).toMatch(validUser.password);
    });

    it('should reject password reset when req.passwordConfirm missing', async () => {
      const res = await supertest(server)
        .post(`/api/v1/users/resetPassword/${token}`)
        .send({ password: 'UpdatedPass12!@' });

      const oldPassword = validUser.password;
      validUser = await User.findById(validUser._id).select('+password');

      expect(res.status).toBe(401);
      expect(oldPassword).toMatch(validUser.password);
    });

    it('should reject password reset when req.password not validated (not strong enough)', async () => {
      const res = await supertest(server)
        .post(`/api/v1/users/resetPassword/${token}`)
        .send({ password: '123', passwordConfirm: '123' });

      const oldPassword = validUser.password;
      validUser = await User.findById(validUser._id).select('+password');

      expect(res.status).toBe(400);
      expect(oldPassword).toMatch(validUser.password);
    });
  });

  describe('Send Email Verification', () => {
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

    it('should successfully send email if email is associated with an existing account', async () => {
      const res = await supertest(server).post('/api/v1/users/sendEmailVerification').send({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch(process.env.DUPLICATE_EMAIL_MESSAGE);
    });

    it('should fake (but not truly send) that email is sent if email is not associated with an existing account', async () => {
      const res = await supertest(server)
        .post('/api/v1/users/sendEmailVerification')
        .send({ email: 'nonexistentEmail@test.io' });

      expect(res.status).toBe(200);
      expect(res.body.token).not.toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch('Faking link sent to email - not truly sent');
    });

    it('should fail but fake sending message if req.body.email is missing', async () => {
      const res = await supertest(server).post('/api/v1/users/sendEmailVerification').send();

      expect(res.status).toBe(200);
      expect(res.body.token).not.toBeDefined();
      expect(res.body.status).toMatch('success');
      expect(res.body.message).toMatch('Faking link sent to email - not truly sent');
    });
  });

  describe('Verify Email', () => {
    let validUser, server;

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully verify email for user when token is valid and not expired', async () => {
      let res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const token = res.body.token;

      res = await supertest(server).get(`/api/v1/users/verifyEmail/${token}`);

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(res.text).toBeDefined();
      expect(validUser.verified).toBe(true);
      expect(validUser.emailVerificationToken).not.toBeDefined();
      expect(validUser.emailVerificationTokenExpires).not.toBeDefined();
    });

    it('should reject verification of email when user token is valid but expired', async () => {
      const actualTokenExpiration = process.env.TOKEN_EXPIRATION;
      process.env.TOKEN_EXPIRATION = 0;

      let res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      const token = res.body.token;
      res = await supertest(server).get(`/api/v1/users/verifyEmail/${token}`);

      process.env.TOKEN_EXPIRATION = actualTokenExpiration;

      res = await supertest(server).get(`/api/v1/users/resetPassword/${token}`);
      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(400);
      expect(validUser.verified).toBe(false);
      expect(validUser.emailVerificationToken).toBeDefined();
      expect(validUser.emailVerificationTokenExpires).toBeDefined();
    });

    it('should reject verification of email when user token is invalid', async () => {
      let res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const token = res.body.token;

      res = await supertest(server).get(`/api/v1/users/verifyEmail/invalidToken`);

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(400);
      expect(validUser.verified).toBe(false);
      expect(validUser.emailVerificationToken).toBeDefined();
      expect(validUser.emailVerificationTokenExpires).toBeDefined();
    });

    it('should reject verification of email when no token is passed', async () => {
      let res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const token = res.body.token;

      res = await supertest(server).get(`/api/v1/users/verifyEmail`);

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(404);
      expect(validUser.verified).toBe(false);
      expect(validUser.emailVerificationToken).toBeDefined();
      expect(validUser.emailVerificationTokenExpires).toBeDefined();
    });
  });

  describe('Get Me', () => {
    let validUser, server, res, jwt, csrf;

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully retrieve current user data if user logged in (JWT valid and not expired) and CSRF token valid and not expired', async () => {
      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      expect(res.status).toBe(200);
      expect(res.body.status).toMatch('success');
      expect(res.body.data.name).toBeDefined();
      expect(res.body.data.phone).toBeDefined();
      expect(res.body.data.email).toBeDefined();
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed password! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed email! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer invalidToken`)
        .send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).post('/api/v1/users/me').send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.message).toMatch('Your token has expired. Please log in again.');
    });

    it('should reject if checkValidCSRFToken middleware not satisfied (CSRF token invalid)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: 'invalid' });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(
        'Unauthorized request. Please log back into your account to refresh your tokens.'
      );
    });

    it('should reject if checkValidCSRFToken middleware not satisfied (CSRF token missing)', async () => {
      res = await supertest(server).post('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Bad request. Missing CSRF token. Please resubmit with valid CSRF token.');
    });

    it('should reject if checkValidCSRFToken middleware not satisfied (CSRF token expired)', async () => {
      validUser = await User.findOne({ email: validUser.email });
      await validUser.setCSRFTokenToExpired();

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(
        'Unauthorized request. Please log back into your account to refresh your tokens.'
      );
    });
  });

  describe('Update Me', () => {
    let validUser, server, res, jwt, csrf;
    const newName = 'UpdatedName';
    const newPhone = '1234567890';

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully update current user data if user logged in (JWT valid and not expired), CSRF token valid and not expired, and data for name and/or phone validated', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
    });

    it('should reject update if user requests change to email property', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, email: 'newEmail@test.io', token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(404);
      expect(validUser).toBeDefined();
      expect(res.body.message).toBe('Not allowed to update password nor email with this route.');
    });

    it('should reject update if user requests change to password property', async () => {
      const newPassword = 'newPassword1!';

      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, password: newPassword, token: csrf });

      const resLoginAfterAttemptedChange = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: newPassword });

      expect(res.status).toBe(404);
      expect(res.body.message).toBe('Not allowed to update password nor email with this route.');

      expect(resLoginAfterAttemptedChange.status).toBe(400);
      expect(resLoginAfterAttemptedChange.body.message).toMatch(
        'Incorrect email or password, email not verified (must be verified to access account), account inactived (to reactivate, please contact customer service using our contact form), or account does not exist.'
      );
    });

    it('should successfully update current user data if conditions met and ignore changes requested for role property', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, role: 'admin', token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.role).toMatch('user');
    });

    it('should successfully update current user data if conditions met and ignore changes requested for emailConfirm property', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, emailConfirm: 'fakeEmail@test.io', token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.emailConfirm).not.toBeDefined();
    });

    it('should successfully update current user data if conditions met and ignore changes requested for passwordConfirm property', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, passwordConfirm: 'fakePassword', token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.passwordConfirm).not.toBeDefined();
    });

    it('should successfully update current user data if conditions met and ignore changes requested for passwordChangedAt property', async () => {
      const dateSetTo = Date.now() - 100000;
      validUser = await User.findOne({ email: validUser.email });
      validUser.setPasswordChangedAtCurrentTime();

      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, passwordChangedAt: dateSetTo, token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.passwordChangedAt.getTime()).not.toBe(dateSetTo);
    });

    it('should successfully update current user data if conditions met and ignore changes requested for emailVerificationToken property', async () => {
      const alteredEmailVerificationToken = 'invalidToken';

      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, emailVerificationToken: alteredEmailVerificationToken, token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.emailVerificationToken).not.toBeDefined();
    });

    it('should successfully update current user data if conditions met and ignore changes requested for emailVerificationTokenExpires property', async () => {
      const alteredEmailVerificationTokenExpires = Date.now();

      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        emailVerificationTokenExpires: alteredEmailVerificationTokenExpires,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.emailVerificationToken).not.toBeDefined();
    });

    it('should successfully update current user data if conditions met and ignore changes requested for csrfToken property', async () => {
      const alteredCSRFToken = 'invalidCSRF';

      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        csrfToken: alteredCSRFToken,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.csrfToken).not.toMatch(alteredCSRFToken);
    });

    it('should successfully update current user data if conditions met and ignore changes requested for csrfTokenExpires property', async () => {
      const alteredCSRFTokenExpires = Date.now();

      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        csrfTokenExpires: alteredCSRFTokenExpires,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.csrfTokenExpires.getTime()).not.toBe(alteredCSRFTokenExpires);
    });

    it('should successfully update current user data if conditions met and ignore changes requested for verified property', async () => {
      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        verified: false,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.verified).toBe(true);
    });

    it('should successfully update current user data if conditions met and ignore changes requested for active property', async () => {
      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        active: false,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(200);
      expect(validUser.name).toMatch(newName);
      expect(validUser.phone).toMatch(newPhone);
      expect(validUser.active).toBe(true);
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed password! Please log in again.');
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .patch('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ name: newName, phone: newPhone, token: csrf });

      validUser = await User.findOne({ email: newEmail });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed email! Please log in again.');
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer invalidToken`).send({
        name: newName,
        phone: newPhone,
        token: csrf,
      });

      expect(res.status).toBe(401);
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).patch('/api/v1/users/me').send({
        name: newName,
        phone: newPhone,
        token: csrf,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
      expect(res.status).toBe(401);
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        token: csrf,
      });

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.message).toMatch('Your token has expired. Please log in again.');
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        token: 'invalidToken',
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(
        'Unauthorized request. Please log back into your account to refresh your tokens.'
      );
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Bad request. Missing CSRF token. Please resubmit with valid CSRF token.');
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      validUser = await User.findOne({ email: validUser.email });
      validUser.setCSRFTokenToExpired();

      res = await supertest(server).patch('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        name: newName,
        phone: newPhone,
        token: 'invalidToken',
      });

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(
        'Unauthorized request. Please log back into your account to refresh your tokens.'
      );
      expect(validUser.name).not.toMatch(newName);
      expect(validUser.phone).not.toMatch(newPhone);
    });
  });

  describe('Delete Me', () => {
    let validUser, server, res, jwt, csrf;

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });
    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully delete (set active property to false) current user data if user logged in (JWT valid and not expired), CSRF token valid and not expired', async () => {
      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      cookies.forEach((element) => {
        const array = element.split(/=/);
        cookiesObj[array[0]] = array.slice(1).join('=');
      });

      const validUserInactive = await User.findOne({ email: validUser.email });

      expect(validUserInactive.active).toBe(false);
      expect(validUserInactive.csrfTokenExpires).toMatchObject(new Date(0));
      expect(cookiesObj.jwt).toMatch('; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly');
      expect(cookiesObj.csrf).toMatch('; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly');
      expect(res.status).toBe(200);

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      expect(res.status).toBe(400);
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed password! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      validUser = await User.findOne({ email: newEmail });

      expect(validUser).toBeDefined();
      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed email! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer invalidToken`)
        .send({ token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
      expect(res.status).toBe(401);
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).delete('/api/v1/users/me').send({ token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
      expect(res.status).toBe(401);
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      res = await supertest(server).delete('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`).send({
        token: csrf,
      });

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      validUser = await User.findOne({ email: validUser.email });

      expect(res.status).toBe(401);
      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: 'invalidCSRF' });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
      expect(res.status).toBe(401);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server).delete('/api/v1/users/me').set('Authorization', `Bearer ${jwt}`);

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
      expect(res.status).toBe(401);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      validUser = await User.findOne({ email: validUser.email });
      await validUser.setCSRFTokenToExpired();

      res = await supertest(server)
        .delete('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      validUser = await User.findOne({ email: validUser.email });

      expect(validUser).toBeDefined();
      expect(validUser.active).toBe(true);
      expect(res.status).toBe(401);
    });
  });

  describe('Update My Password', () => {
    let validUser, server, res, jwt, csrf;
    const newPassword = 'NewPassword1!';

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });
    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully update current user password if user logged in (JWT valid and not expired), CSRF token valid and not expired, hashed value for req.body.currentPassword === user.password, and password/passwordConfirm match and are validated successfully', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch('Password updated successfully.');

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

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

    it('should reject updating current user password if hashed req.body.currentPassword !== user.password', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: 'incorrectPassword',
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject updating current user password if req.body.currentPassword missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ password: newPassword, passwordConfirm: newPassword, token: csrf });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject updating current user password if req.body.password missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ passwordCurrent: validUser.password, passwordConfirm: newPassword, token: csrf });

      expect(res.status).toBe(400);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject updating current user password if req.body.passwordConfirm missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(400);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject updating current user password if req.body.password !== req.body.passwordConfirm', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: 'mismatchedNewPassword',
          token: csrf,
        });

      expect(res.status).toBe(400);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject updating current user password if req.body.password not strong enough (does not pass validation)', async () => {
      const weakPassword = '123';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: weakPassword,
          passwordConfirm: weakPassword,
          token: csrf,
        });

      expect(res.status).toBe(400);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: newPassword,
          password: 'RepeatingPassChange1!',
          passwordConfirm: 'RepeatingPassChange1!',
          token: csrf,
        });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed password! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed email! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer incorrectJWT`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).patch('/api/v1/users/me/updatePassword').send({
        passwordCurrent: validUser.password,
        password: newPassword,
        passwordConfirm: newPassword,
        token: csrf,
      });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: 'mismatchedCSRF',
        });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
        });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      validUser = await User.findOne({ email: validUser.email });
      await validUser.setCSRFTokenToExpired();

      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      expect(res.status).toBe(401);

      res = await supertest(server).post('/api/v1/users/login').send({ email: validUser.email, password: newPassword });

      const cookies = res.header['set-cookie'];
      const cookiesObj = {};

      if (cookies) {
        cookies.forEach((element) => {
          const array = element.split(/=/);
          cookiesObj[array[0]] = array.slice(1).join('=');
          expect(cookiesObj.jwt).not.toBeDefined();
          expect(cookiesObj.csrf).not.toBeDefined();
        });
      }

      expect(res.status).toBe(400);
    });
  });

  describe('Update My Email', () => {
    let validUser, existingUser, server, res, jwt, csrf;
    const newEmail = 'newEmail2@test.io';
    const newEmailExisting = 'newEmail1@test.io';

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      existingUser = {
        name: 'testing testing',
        email: 'newEmail1@test.io',
        emailConfirm: 'newEmail1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);
      await supertest(server).post('/api/v1/users/signup').send(existingUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully update current user email if user logged in (JWT valid and not expired), CSRF token valid and not expired, hashed value for req.body.password === user.password, and email/emailConfirm match and are validated successfully', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(200);

      res = await supertest(server).post('/api/v1/users/login').send({ email: newEmail, password: validUser.password });

      expect(res.status).toBe(400);
      expect(await User.findOne({ email: validUser.email })).toBeNull();
      expect(await User.findOne({ email: newEmail })).not.toBeNull();
    });

    it('should reject updating current user email if email already in use', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmailExisting, emailConfirm: newEmailExisting, password: validUser.password, token: csrf });

      validUser = await User.findOne({ email: validUser.email });
      existingUser = await User.findOne({ email: newEmailExisting });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(process.env.DUPLICATE_EMAIL_MESSAGE);
      expect(validUser._id).not.toBe(existingUser._id);
    });

    it('should reject updating current user email if hashed req.body.password !== user.password', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: 'mismatched', token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Incorrect password. Please resubmit with your correct password.');
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject updating current user email if req.body.password missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Cannot update email. Missing one or more of: email, emailConfirm, password.');
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject updating current user email if req.body.email missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Cannot update email. Missing one or more of: email, emailConfirm, password.');
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject updating current user email if req.body.emailConfirm missing', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Cannot update email. Missing one or more of: email, emailConfirm, password.');
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject updating current user email if req.body.email !== req.body.emailConfirm', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: 'mismatched@test.io', password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(
        'Email and email confirmation mismatch. Please check these values are the same and resubmit.'
      );
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject updating current user email if req.body.email not a valid email (does not pass validation)', async () => {
      const invalidEmail = 'invalidEmail';

      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: invalidEmail, emailConfirm: invalidEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(
        'User validation failed: email: Email is invalid. Please provide a valid email address'
      );
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: newPassword, token: csrf });

      const userCurrentEmail = await User.findOne({ email: validUser.email });
      const userNewEmail = await User.findOne({ email: newEmail });

      expect(userCurrentEmail).not.toBeNull();
      expect(userNewEmail).toBeNull();
      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed password! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      const newEmail2 = 'newEmailtake2@test.io';

      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail2, emailConfirm: newEmail2, password: validUser.password, token: csrf });

      const userNewEmail = await User.findOne({ email: newEmail });
      const userNewEmail2 = await User.findOne({ email: newEmail2 });

      expect(userNewEmail).not.toBeNull();
      expect(userNewEmail2).toBeNull();
      expect(res.status).toBe(401);
      expect(res.body.message).toMatch('Recently changed email! Please log in again.');
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer invalidJWT`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: 'invalidToken' });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      validUser = await User.findOne({ email: validUser.email });
      await validUser.setCSRFTokenToExpired();

      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      expect(res.status).toBe(401);
      expect(await User.findOne({ email: validUser.email })).not.toBeNull();
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });
  });

  describe('Admin Get All Users', () => {
    let validUser, server, res, jwt, csrf, userObj;

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      userObj = await User.findOne({ email: validUser.email });
      await userObj.setRole('admin');

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully complete request and return all users if current logged in user (JWT valid) has role admin and CSRF token valid', async () => {
      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(200);
      expect(res.body.status).toMatch('success');
      expect(res.body.numUsers).toBe(1);
      expect(res.body.data.data).toBeDefined();
    });

    it('should reject currently logged in user is not an admin', async () => {
      await userObj.setRole('user');

      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(403);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/')
        .set('Authorization', `Bearer invalidToken`)
        .send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).post('/api/v1/users/').send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: 'invalidToken' });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`);

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      await userObj.setCSRFTokenToExpired();

      res = await supertest(server).post('/api/v1/users/').set('Authorization', `Bearer ${jwt}`).send({ token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });
  });

  describe('Admin Get Single User', () => {
    let server, validUser, queryUser, userObj, res, jwt, csrf;

    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      queryUser = {
        name: 'test test',
        email: 'testing2@test.io',
        emailConfirm: 'testing2@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      await supertest(server).post('/api/v1/users/signup').send(queryUser);
      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      userObj = await User.findOne({ email: validUser.email });

      await userObj.setRole('admin');

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully return user information for id if currently logged in user (JWT valid) is an admin (role) and CSRF token valid', async () => {
      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      console.log(res);

      expect(res.status).toBe(200);
      expect(res.body.status).toMatch('success');
      expect(res.body.data.data.email).toMatch(queryUser.email);
    });

    it('should reject if the req.params.email is not an email address associated with an account', async () => {
      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: 'invalidEmail@test.io', token: csrf });

      expect(res.status).toBe(404);
      expect(res.body.message).toBe('No user found for the email provided.');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer invalidJWT`)
        .send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server).post(`/api/v1/users/user`).send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;

      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: 'invalidCSRF' });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      await userObj.setCSRFTokenToExpired();

      res = await supertest(server)
        .post(`/api/v1/users/user`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      expect(res.status).toBe(401);
      expect(res.body.status).toMatch('failed');
      expect(res.body.data).not.toBeDefined();
    });
  });

  describe('Admin Update User', () => {
    let server, validUser, queryUser, userObj, res, jwt, csrf;
    const newName = 'New Name';
    const newPhone = '1234567890';
    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      queryUser = {
        name: 'test test',
        email: 'testing2@test.io',
        emailConfirm: 'testing2@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      await supertest(server).post('/api/v1/users/signup').send(queryUser);
      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      userObj = await User.findOne({ email: validUser.email });

      await userObj.setRole('admin');

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should update user successfully if middleware conditions satisfied, and req.body.phone is valid', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.phone).toMatch(newPhone);
    });

    it('should update user successfully if middleware conditions satisfied, and req.body.name is valid', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
    });

    it('should update user successfully if middleware conditions satisfied, and req.body.name and req.body.phone are valid', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
    });

    it('should reject when req.body.email is passed due to middleware', async () => {
      const newEmail = 'newEmail@test.io';

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, email: newEmail, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(404);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
      expect(await User.findOne({ email: newEmail })).toBeNull();
    });

    it('should ignore req.body.emailConfirm and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newEmailConfirm = 'newEmail@test.io';

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        emailConfirm: newEmailConfirm,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email }).select('+emailConfirm');

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.emailConfirm).not.toBeDefined();
    });

    it('should ignore req.body.emailChangedAt and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newEmailChangedAt = Date.now();

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        emailChangedAt: newEmailChangedAt,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email }).select('+emailChangedAt');

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.emailChangedAt).not.toBeDefined();
    });

    it('should ignore req.body.previousEmails and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPreviousEmails = ['previousEmail1@test.io', 'previousEmail2@test.io'];

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        previousEmails: newPreviousEmails,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.previousEmails).not.toMatchObject(newPreviousEmails);
    });

    it('should ignore req.body.role and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newRole = 'admin';

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, role: newRole, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.role).not.toMatch(newRole);
    });

    it('should ignore req.body.password and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPassword = 'newPassword1@';

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, password: newPassword, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email }).select('+password');

      expect(res.status).toBe(404);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
      expect(queryUser.password).not.toMatch(newPassword);
    });

    it('should ignore req.body.passwordConfirm and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPasswordConfirm = 'newPassword1@';

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        passwordConfirm: newPasswordConfirm,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email }).select('+passwordConfirm');

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.passwordConfirm).not.toBeDefined();
    });

    it('should ignore req.body.passwordChangedAt and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPasswordChangedAt = Date.now();
      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        passwordChangedAt: newPasswordChangedAt,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.passwordChangedAt).not.toBeDefined();
    });

    it('should ignore req.body.passwordResetToken and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPasswordResetToken = 'randomToken';

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        passwordResetToken: newPasswordResetToken,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.passwordResetToken).not.toBeDefined();
    });

    it('should ignore req.body.passwordResetTokenExpires and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newPasswordResetExpires = Date.now();

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        passwordResetExpires: newPasswordResetExpires,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.passwordResetExpires).not.toBeDefined();
    });

    it('should ignore req.body.csrfToken and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newCSRFToken = 'newCSRFToken';

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, csrfToken: newCSRFToken, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.csrfToken).not.toBeDefined(); // unverified user - has never logged in - no csrfToken generated at this point
    });

    it('should ignore req.body.csrfTokenExpires and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newCSRFTokenExpires = Date.now();

      res = await supertest(server).patch(`/api/v1/users/updateUser`).set('Authorization', `Bearer ${jwt}`).send({
        userEmail: queryUser.email,
        name: newName,
        phone: newPhone,
        csrfTokenExpires: newCSRFTokenExpires,
        token: csrf,
      });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.csrfTokenExpires).not.toBeDefined();
    });

    it('should ignore req.body.verified and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newVerified = true;

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, verified: newVerified, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.verified).not.toBe(newVerified);
    });

    it('should ignore req.body.active and update user successfully if middleware conditions satisfied and req.body.name and req.body.phone are valid', async () => {
      const newActive = false;

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, active: newActive, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.name).toMatch(newName);
      expect(queryUser.phone).toMatch(newPhone);
      expect(queryUser.active).not.toBe(newActive);
    });

    it('should reject if the req.params.email is not an email address associated with an account', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: 'invalidEmail@test.io', name: newName, phone: newPhone, token: csrf });

      expect(res.status).toBe(404);
      expect(res.body.message).toBe('No user found for the email provided.');
      expect(res.body.data).not.toBeDefined();
    });

    it('should reject if req.body.name is not a valid name', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: '123', phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(400);
      expect(queryUser.name).not.toMatch('123');
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if req.body.phone is not a valid phone number', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: '123', token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(400);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch('123');
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer invalidJWT`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: 'invalidCSRF' });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      await userObj.setCSRFTokenToExpired();

      res = await supertest(server)
        .patch(`/api/v1/users/updateUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, name: newName, phone: newPhone, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.name).not.toMatch(newName);
      expect(queryUser.phone).not.toMatch(newPhone);
    });
  });

  describe('Admin Delete User', () => {
    let server, validUser, queryUser, userObj, res, jwt, csrf;
    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      queryUser = {
        name: 'test test',
        email: 'testing2@test.io',
        emailConfirm: 'testing2@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      await supertest(server).post('/api/v1/users/signup').send(queryUser);
      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      userObj = await User.findOne({ email: validUser.email });

      await userObj.setRole('admin');

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully inactivate user (set active to false) if currently logged in user (JWT valid) is admin, CSRF token valid, and req.body.userEmail is valid', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch('Successfully inactivated account.');
      expect(queryUser.active).toBe(false);
    });

    it('should reject if req.body.userEmail is not associated with an account', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: 'invalidEmail2@test.io', token: csrf });

      expect(res.status).toBe(404);
      expect(res.body.message).toBe('No user found for the email provided.');
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer invalidJWT`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: 'invalidCSRF' });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      await userObj.setCSRFTokenToExpired();

      res = await supertest(server)
        .delete(`/api/v1/users/deleteUser`)
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(true);
    });
  });

  describe('Admin Reactivate User', () => {
    let server, validUser, queryUser, userObj, queryObj, res, jwt, csrf;
    beforeEach(async () => {
      server = await getServer();

      validUser = {
        name: 'testing testing',
        email: 'testing1@test.io',
        emailConfirm: 'testing1@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      queryUser = {
        name: 'test test',
        email: 'testing2@test.io',
        emailConfirm: 'testing2@test.io',
        phone: '5555555555',
        password: 'Testing1234!@#',
        passwordConfirm: 'Testing1234!@#',
      };

      await supertest(server).post('/api/v1/users/signup').send(queryUser);
      res = await supertest(server).post('/api/v1/users/signup').send(validUser);

      const verifyToken = res.body.token;
      await supertest(server).get(`/api/v1/users/verifyEmail/${verifyToken}`);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      userObj = await User.findOne({ email: validUser.email });
      queryObj = await User.findOne({ email: queryUser.email });

      await userObj.setRole('admin');
      await queryObj.setActiveFalse();

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
    });

    afterEach(async () => {
      await User.deleteMany({});
      await server.close();
    });

    it('should successfully reactivate user (set active status to true) if currently logged in (JWT valid) user is admin, CSRF token valid, and req.body.userEmail belongs to an existing account', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(200);
      expect(queryUser.active).toBe(true);
    });

    it('should reject if req.body.userEmail does not belong to an account in the database', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: 'invalidEmail@test.io', token: csrf });

      expect(res.status).toBe(404);
      expect(res.body.message).toMatch('No user found for the email provided.');
    });

    it('should reject if protect middleware not satisfied (Changed password)', async () => {
      const newPassword = 'NewPassword1@';
      res = await supertest(server)
        .patch('/api/v1/users/me/updatePassword')
        .set('Authorization', `Bearer ${jwt}`)
        .send({
          passwordCurrent: validUser.password,
          password: newPassword,
          passwordConfirm: newPassword,
          token: csrf,
        });

      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect middleware not satisfied (Changed email)', async () => {
      const newEmail = 'newEmail@test.io';
      res = await supertest(server)
        .patch('/api/v1/users/me/updateEmail')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ email: newEmail, emailConfirm: newEmail, password: validUser.password, token: csrf });

      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect middleware not satisfied (JWT invalid)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer invalidJWT`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect middleware not satisfied (JWT missing)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect middleware not satisfied (JWT expired)', async () => {
      const actualJWTExpiration = process.env.JWT_EXPIRES_IN;
      process.env.JWT_EXPIRES_IN = 0;

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      jwt = res.body.data.token;
      csrf = res.body.data.csrfToken;
      process.env.JWT_EXPIRES_IN = actualJWTExpiration;

      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: 'invalidCSRF' });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', async () => {
      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });

    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', async () => {
      await userObj.setCSRFTokenToExpired();

      res = await supertest(server)
        .post('/api/v1/users/reactivateUser')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ userEmail: queryUser.email, token: csrf });

      queryUser = await User.findOne({ email: queryUser.email });

      expect(res.status).toBe(401);
      expect(queryUser.active).toBe(false);
    });
  });

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.disconnect();
  });
});
