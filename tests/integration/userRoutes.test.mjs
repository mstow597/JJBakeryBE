import supertest from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
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

      expect(res.status).toBe(401);
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

      expect(res.status).toBe(401);
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

      expect(res.status).toBe(401);
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
      expect(res.body.message).toMatch('Link sent to email!(NODE_ENV test only)');
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

      expect(resLoginAfterAttemptedChange.status).toBe(401);
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

      expect(validUserInactive).toBeNull();
      expect(cookiesObj.jwt).toMatch('; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly');
      expect(cookiesObj.csrf).toMatch('; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly');
      expect(res.status).toBe(200);

      res = await supertest(server)
        .post('/api/v1/users/me')
        .set('Authorization', `Bearer ${jwt}`)
        .send({ token: csrf });

      console.log(res);

      res = await supertest(server)
        .post('/api/v1/users/login')
        .send({ email: validUser.email, password: validUser.password });

      expect(res.status).toBe(401);
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
    it('should successfully update current user password if user logged in (JWT valid and not expired), CSRF token valid and not expired, hashed value for req.body.currentPassword === user.password, and password/passwordConfirm match and are validated successfully', () => {});
    it('should reject updating current user password if hashed req.body.currentPassword !== user.password', () => {});
    it('should reject updating current user password if req.body.currentPassword missing', () => {});
    it('should reject updating current user password if req.body.password missing', () => {});
    it('should reject updating current user password if req.body.passwordConfirm missing', () => {});
    it('should reject updating current user password if req.body.password !== req.body.passwordConfirm', () => {});
    it('should reject updating current user password if req.body.password not strong enough (does not pass validation)', () => {});
    it('should reject if protect middleware not satisfied (JWT invalid)', () => {});
    it('should reject if protect middleware not satisfied (JWT missing)', () => {});
    it('should reject if protect middleware not satisfied (JWT expired)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', () => {});
  });

  describe('Update My Email', () => {
    it('should successfully update current user email if user logged in (JWT valid and not expired), CSRF token valid and not expired, hashed value for req.body.password === user.password, and email/emailConfirm match and are validated successfully', () => {});
    it('should reject updating current user password if hashed req.body.password !== user.password', () => {});
    it('should reject updating current user password if req.body.password missing', () => {});
    it('should reject updating current user password if req.body.email missing', () => {});
    it('should reject updating current user password if req.body.emailConfirm missing', () => {});
    it('should reject updating current user password if req.body.email !== req.body.emailConfirm', () => {});
    it('should reject updating current user password if req.body.email not a valid email (does not pass validation)', () => {});
    it('should reject if protect middleware not satisfied (JWT invalid)', () => {});
    it('should reject if protect middleware not satisfied (JWT missing)', () => {});
    it('should reject if protect middleware not satisfied (JWT expired)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token mismatch)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token missing)', () => {});
    it('should reject if protect checkValidCSRFToken not satisfied (CSRF token expired)', () => {});
  });

  describe('Admin Get All Users', () => {});

  describe('Admin Get Single User', () => {});

  describe('Admin Update User', () => {});

  describe('Admin Delete User', () => {});

  afterAll(async () => {
    await User.deleteMany({});
    await mongoose.disconnect();
  });
});
