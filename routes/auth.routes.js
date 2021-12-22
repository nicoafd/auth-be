const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;

  // verifications of what was sent
  if (!username) {
    return res.status(400).json({
      errorMessage: "Hey! We need a username from you....buddy!",
    });
  }

  if (password.length < 8) {
    return res.json({ errorMessage: "That password is not safe...guy!" });
  }

  User.findOne({ username: username }).then((foundUser) => {
    if (foundUser) {
      return res.json({
        errorMessage: "The username is already taken, Kim.",
      });
    }

    // encrypt the password
    const saltRounds = 10;
    return bcrypt
      .genSalt(saltRounds)
      .then((salt) => bcrypt.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({ username, password: hashedPassword });
      })
      .then((user) => {
        req.session.user = user;
        res.status(201).json(user);
      })
      .catch((error) => {
        return res.json({
          errorMessage: `Something went wrong when creating the user. Sorry. ${error.message}`,
        });
      });
  });

  // create the user
});

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      errorMessage: `Hey! Did you forget something? cough cough ${
        username ? "password" : password ? "username and password" : "username"
      }`,
    });
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.json({
          errorMessage: "Oy! Mate! You don't have an account!",
        });
      }

      bcrypt.compare(password, user.password).then((isSamePassword) => {
        if (!isSamePassword) {
          return res.json({ errorMessage: "Wrong password, mate." });
        }

        req.session.user = user;
        return res.json(user);
      });
    })
    .catch((error) => {
      next(error);
    });
});

router.post("/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        errorMessage: `Something went wrong with the logout: ${error.message}`,
      });
    }
    res.json({ successMessage: "Logged out!" });
  });
});

router.get("/loggedin", (req, res, next) => {
  if (req.session.user) {
    return res.json({ user: req.session.user });
  }
  res.status(403).json({ errorMessage: "You're not authenticated." });
});

module.exports = router;