const { Router } = require("express");
const User = require("../models/user");

const router = Router();

// GET Signin Page
router.get("/signin", (req, res) => {
  return res.render("signin");
});

// GET Signup Page
router.get("/signup", (req, res) => {
  return res.render("signup");
});

router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const token = await User.matchPasswordAndGenerateToken(email, password);
    return res.cookie("token", token).redirect("/");
  } catch (error) {
    return res.render("signin", {
      error: "Incorrect Email Or Password",
    });
  }
});

router.get("/logout", (req,res) => {
  res.clearCookie("token").redirect("/");
})

router.post("/signup", async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    await User.create({
      fullName,
      email,
      password,
    });
    return res.redirect("/");
  } catch (error) {
    return res.render("signup", {
      error: "An error occurred while creating the account. Please try again.",
    });
  }
});

module.exports = router;
