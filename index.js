const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const User = require("./models/user");
const ejs = require("ejs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
dotenv.config();

const app = express();
app.set("view engine", "ejs");

const isAuthenticated = (req, res, next) => {
  try {
    const user = jwt.verify(req.headers.token, process.env.JWT_SECRET_KEY);
    req.user = user;
  } catch (error) {
    return res.send({ status: "FAIL", message: "Please login first" });
  }
  next();
};

const isAuthorized = (req, res, next) => {
  console.log(req.user);
  if (Boolean((isAdmin = req.user.isAdmin))) {
    return next();
  }
  return res.send({ status: "FAIL", message: "Access Denied" });
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("./public"));

app.get("/", (req, res) => {
  res.send({ message: "All Good!" });
});

app.post("/register", async (req, res) => {
  const { email, password, isAdmin } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.send({
        status: "FAIL",
        message: "User already exists with this email",
      });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    await User.create({
      email,
      password: encryptedPassword,
      isAdmin,
    });
    res.send({ status: "SUCCESS", message: "User created successfully!" });
  } catch (error) {
    res.send({ error });
  }
});

// app.post("/login", (req, res) => {
//   const { email, password } = req.body;
//   User.findOne({ email })
//     .then((user) => {
//       if (user.password === password) {
//         return res.send({
//           status: "SUCCESS",
//           message: "User logged in successfully",
//         });
//       }
//       return res.send({ status: "FAIL", message: "Incorrect Password" });
//     })
//     .catch((error) => console.log(error));
// });

//or

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      let passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        const { isAdmin } = user;
        const jwtToken = jwt.sign(
          { email, isAdmin },
          process.env.JWT_SECRET_KEY,
          { expiresIn: 60 }
        );
        return res.send({
          status: "SUCCESS",
          message: "User logged in successfully",
          jwtToken,
        });
      }
    }
    res.send({ status: "FAIL", message: "Incorrect Credentials" });
  } catch (error) {
    req.send({ error });
  }
});

// Only logged-in users can access
app.get("/private-route", isAuthenticated, (req, res) => {
  res.send({ message: "Welcome User!" });
});

// Only logged-in + admin users can access
app.get("/admin-route", isAuthenticated, isAuthorized, (req, res) => {
  res.send({ message: "Welcome Admin!" });
});

app.listen(process.env.PORT, () => {
  mongoose
    .connect(process.env.MONGO_DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => console.log(`Server is running on port:${process.env.PORT}`))
    .catch((err) => console.log(err));
});

/*
  ## Authentication and Authorization
  - Authentication: Verify user's identity (who are you ?) (Whether you have account or not / you can login/signup  or not)
  - Authorization: Check access of authenticated user (What access does the user have?)(Whether you have access to that after login/signup)
  
  # Let say an example of Hotstar:
  - Authentication: When you visit the Hotstar App then it will check you have account or not/ You can login/signup or not.
  - Authorization: Once you logged in Hotstar have premium and premium plus content then 
        and if you are going to play premium plus content then that time it will check that you have access or not for premium content.

  # JSON Web Token (JWT)
  # Securing user's password
  # bcrypt
*/
