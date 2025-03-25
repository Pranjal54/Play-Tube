import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";  
import jwt from "jsonwebtoken";

const linkSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  url: {
    type: String,
    required: true,
  },
});

const watchHistorySchema = new Schema(
  {
    video: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Video",
    },
  },
  { timestamps: true }
);

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    password: {
      type: String,
      required: true,
    },
    watchHistory: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Video",
      },
    ],
    avatar: {
      type: String,
      required: true,
    },
    coverImage: {
      type: String,
    },
    description: {
      type: String,
      default: "",
    },
    links: [linkSchema],
    refreshToken: {
      type: String,
    },
  },
  { timestamps: true }
);

// ✅ Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

// ✅ Corrected function definition
userSchema.methods.isPasswordCorrect = async function (password) {
  return bcrypt.compare(password, this.password);
};

// ✅ Generate Access Token
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1h", // Default to 1 hour if undefined
    }
  );
};

// ✅ Generate Refresh Token
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "7d", // Default to 7 days if undefined
    }
  );
};

export const User = mongoose.model("User", userSchema);
