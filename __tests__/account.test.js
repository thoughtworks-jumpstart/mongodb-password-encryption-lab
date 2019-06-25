const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const mongoose = require('mongoose');
const account = require('../src/account');

describe('insert', () => {
  let connection;
  let db;
  let Users;

  beforeAll(async () => {
    connection = await MongoClient.connect(global.__MONGO_URI__, {
      useNewUrlParser: true,
    });
    db = await connection.db(global.__MONGO_DB_NAME__);
  });

  afterAll(async () => {
    mongoose.connection.close();
    await connection.close();
  });

  beforeEach(() => {
    db.dropDatabase();
    Users = db.collection('users');
  });

  describe('account', () => {
    let username, password, user;
    beforeEach(() => {
      username = 'Peter Oh';
      password = 'my-secret';
      user = { username, password };
    });

    // Lab 1
    describe('simple strategy', () => {
      it('signup should store the username and password into the database', async () => {
        const newUser = { username: 'John Smith', password: 'secret' };
        await account.simpleSignUp(newUser);

        const insertedUser = await Users.findOne(newUser);
        expect(insertedUser).toMatchObject(newUser);
      });

      it('login should retrieve the user from the database', async () => {
        const newUser = { username: 'John Smith', password: 'secret' };
        await account.simpleSignUp(newUser);

        const loggedInUser = await account.simpleLogin(newUser);
        expect(loggedInUser).toMatchObject(newUser);
      });
    });

    // Lab 2
    xdescribe('hash', () => {
      const cryptoAlgo = 'sha256';
      let hash, digest, userWithDigest;

      beforeEach(() => {
        hash = crypto.createHash(cryptoAlgo);
        hash.update(password);
        digest = hash.digest('hex');
        userWithDigest = { username, password: digest };
      });

      it('should store hashed password base on sha256 and store into db', async () => {
        await account.hashSignUp(user);

        let insertedUser = await Users.findOne(user);
        expect(insertedUser).toBeFalsy();

        insertedUser = await Users.findOne(userWithDigest);
        expect(insertedUser).toMatchObject(userWithDigest);
      });

      it('should retrieve user with name and without password', async () => {
        await account.hashSignUp(user);
        const loginedUser = await account.hashLogin(user);
        expect(loginedUser.username).toEqual(username);
        expect(loginedUser.password).toBeFalsy();
      });
    });

    // Lab 3
    xdescribe('hash with secret', () => {
      const appHashSecret = 'abcdefg';

      it('should sign up with with hash password with secret', async () => {
        const digest = crypto
          .createHmac('sha256', appHashSecret)
          .update(password)
          .digest('hex');

        await account.hashWithSecretSignUp(user);

        let foundUser = await Users.findOne(user);
        expect(foundUser).toBeFalsy();

        foundUser = await Users.findOne({
          username: user.username,
          password: digest,
        });
        expect(foundUser).toMatchObject(foundUser);
      });

      // Lab 4
      it('should login with hash password and secret', async () => {
        await account.hashWithSecretSignUp(user);
        const loginedUser = await account.hashWithSecretLogin(user);
        expect(loginedUser.username).toEqual(username);
        expect(loginedUser.password).toBeFalsy();
      });
    });

    // Lab 5
    xdescribe('hash with salt', () => {
      it('should save username and password with random salt', async () => {
        const createdUser = await account.hashSaltSignUp(user);

        const digest = crypto
          .createHmac('sha256', createdUser.salt)
          .update(user.password)
          .digest('hex');

        let foundUser = await Users.findOne(createdUser);
        expect(foundUser.username).toEqual(user.username);
        expect(foundUser.password).toEqual(digest);
        expect(foundUser.salt).toHaveLength(64);
      });

      it('should be able to verify user password base on salt', async () => {
        await account.hashSaltSignUp(user);
        const loginedUser = await account.hashSaltLogin(user);
        expect(loginedUser.username).toEqual(user.username);
        expect(loginedUser.password).toBeFalsy();
      });

      it('should verify false if userpassword is wrong', async () => {
        await account.hashSaltSignUp(user);
        const loginedUser = await account.hashSaltLogin({
          username: user.username,
          password: 'wrong password',
        });
        expect(loginedUser).toBeFalsy();
      });
    });

    // lab 6
    xdescribe('bcrypt', () => {
      it('should be able to login and logout', async () => {
        console.log(await account.bcryptSignup(user));
        const signinUser = await account.bcryptLogin(user);
        expect(signinUser.username).toEqual(user.username);
      });

      it('should not be able to login if wrong password', async () => {
        await account.bcryptSignup(user);
        user.password = 'wrong password';
        const signinUser = await account.bcryptLogin(user);
        expect(signinUser).toBeFalsy();
      });
    });
  });
});
