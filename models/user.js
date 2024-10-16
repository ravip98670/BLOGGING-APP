const { createHmac, randomBytes } = require("crypto");
const { Schema, model } = require("mongoose");
const { createTokenForUser } = require("../services/auth");

const userSchema = new Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    salt: {
      type: String,
    },
    password: {
      type: String,
      required: true,
    },
    profileImageURL: {
      type: String,
      default: "/images/default.png",
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER",
    },
  },
  { timestamps: true }
);

// Hash the password before saving
userSchema.pre("save", function (next) {
  const user = this;

  // Only hash the password if it has been modified (or is new)
  if (!user.isModified("password")) return next();

  // Generate a new salt and hash the password
  const salt = randomBytes(16).toString("hex");
  const hashedPassword = createHmac("sha256", salt)
    .update(user.password)
    .digest("hex");

  // Set the salt and hashed password
  user.salt = salt;
  user.password = hashedPassword;

  next();
});

// Method to match provided password with the hashed password
userSchema.static("matchPasswordAndGenerateToken", async function (email, password) {
  const user = await this.findOne({ email });
  if (!user) throw new Error("User not found!");

  const userProvHashed = createHmac("sha256", user.salt)
    .update(password)
    .digest("hex");

  if (user.password !== userProvHashed) throw new Error("Incorrect Password");


  const token = createTokenForUser(user);
 
  return token;
});

const User = model("User", userSchema);

module.exports = User;
