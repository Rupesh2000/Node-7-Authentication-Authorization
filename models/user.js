const mongoose = require("mongoose");

const User = mongoose.model("User", {
  email: String,
  password: String,
  isAdmin: Boolean,
});

module.exports = User;
