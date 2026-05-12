import express, { json } from "express";
import cors from "cors";
import User from "./models/User.js";
import connectDB from "./connectdb.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt, { compare } from "bcrypt";
import Complaint from "./models/Complaint.js";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(
  cors({
    origin: [
    "http://localhost:5173", // ✅ exact frontend URL
    "http://localhost:5174", // ✅ exact frontend URL
    ],
    credentials: true, // ✅ allow cookies
  }),
);
app.use(express.json());
app.use(cookieParser());
connectDB();

const authMiddleware = (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const sendEmail = async (to, subject, text) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "xyza22643@gmail.com",
        pass: process.env.password,
      },
    });

    const mailOptions = {
      from: "xyza22643@gmail.com",
      to: to,
      subject: subject,
      text: text,
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");
  } catch (err) {
    console.log("Email error:", err);
  }
};

app.get("/", async (req, res) => {
  res.send("this is / route");
});

// to check that the user is logged in or not to show profile or login button
app.get("/check_login", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ loggedIn: false });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    res.json({ loggedIn: true });
  } catch {
    res.status(401).json({ loggedIn: false });
  }
});

app.get("/allcomplains", authMiddleware, async (req, res) => {
  const allcomplaints = await User.findOne({ _id: req.user.userId }).populate(
    "usercomplaints",
  );
  return res.json(allcomplaints);
});

app.get("/userprofile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.user.userId });
    return res.json(user);
  } catch (err) {
    return res.status(400).json({ message: "something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({
      email,
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // compare the password to the bcrypt password

    const comparePassword = await bcrypt.compare(password, user.password);

    // ⚠️ here you should compare password (bcrypt later)
    if (!comparePassword) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    // 🍪 Store in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // 👉 make true in production (HTTPS)
      sameSite: "strict",
    });

    return res.json({ message: "Login successful" });
  } catch (err) {
    return res.status(500).json({ message: "something wrong when user login" });
  }
});

app.post("/api/complaints", authMiddleware, async (req, res) => {
  const { name, rollno, department, complainttype, title, describe } = req.body;

  try {
    const complaint = await Complaint.create({
      name,
      rollno,
      department,
      complainttype,
      title,
      describe,
      user: req.user.userId, // 🔥 link user
    });

    await User.findByIdAndUpdate(req.user.userId, {
      $push: { usercomplaints: complaint._id },
    });

    return res
      .status(200)
      .json({ message: "Complaint submitted successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { name, username, email, password, contact } = req.body;

    // 🔹 Required fields check
    if (!name || !username || !email || !password || !contact) {
      return res.status(400).json({ message: "All fields must be filled" });
    }

    // 🔹 Trim check (only for strings)
    if (!name.trim() || !username.trim() || !email.trim() || !password.trim()) {
      return res.status(400).json({ message: "Fields cannot be empty" });
    }

    // 🔹 Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // 🔹 Password length
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    // 🔹 Check duplicate user
    const existingUser = await User.findOne({
      $or: [{ email }, { username }, { contact }],
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // 🔐 Hash password (FIXED: added await)
    const hashedPassword = await bcrypt.hash(password, 10);

    // 👤 Create user
    const user = await User.create({
      name: name.trim(),
      username: username.trim(),
      email: email.trim(),
      contact,
      password: hashedPassword,
    });

    // 🔑 Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    // 🍪 Store in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // 👉 make true in production (HTTPS)
      sameSite: "strict",
    });

    // ✅ Response
    return res.status(201).json({
      message: "User registered successfully",
      userId: user._id,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/userlogout", authMiddleware, (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });
  res.status(200).json({ message: "user logged out successfully" });
});

app.patch("/updateprofile", authMiddleware, async (req, res) => {
  const { name, email, username, contact } = req.body;

  if (!name.trim() > 0 || !email.trim() > 0 || !username.trim() > 0) {
    return res.status(400).send({ message: "all fields are required" });
  }

  if (!/^[0-9]{10}$/.test(contact)) {
    return res.status(400).send("Enter valid 10 digit number");
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).send("enter valid number");
  }

  const updates = {
    name,
    email,
    username,
    contact,
  };

  const updatedUser = await User.updateOne(
    { _id: req.user.userId },
    { $set: updates },
  );
  console.log(updatedUser);

  return res.status(200).json({ message: "user updated successfully" });
});

app.patch("/updatepassword", authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    // 1. Check empty fields
    if (!oldPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // 2. Password length
    if (newPassword.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters",
      });
    }

    // 3. Confirm password match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        message: "New password and confirm password do not match",
      });
    }

    // 4. Get user password only
    const user = await User.findById(req.user.userId).select("password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 5. Compare old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Your old password is incorrect",
      });
    }

    // 6. New password must be different
    if (oldPassword === newPassword) {
      return res.status(400).json({
        message: "New password must be different from old password",
      });
    }

    // 7. Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 8. Update password
    await User.findByIdAndUpdate(req.user.userId, {
      $set: { password: hashedPassword },
    });

    return res.status(200).json({
      message: "Password updated successfully",
    });
  } catch (err) {
    console.error("Update password error:", err);
    return res.status(500).json({
      message: "Server error while updating password",
    });
  }
});

app.post("/forgotpassword", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "Email not found" });
    }

    // Generate reset token
    const token = crypto.randomBytes(32).toString("hex");

    // Save token in DB (you should create resetToken field)
    user.resetToken = token;
    user.resetTokenExpire = Date.now() + 10 * 60 * 1000; // 10 min
    await user.save();

    const resetLink = `http://localhost:5173/resetpassword/${token}`;

    await sendEmail(
      email,
      "Password Reset",
      `Click this link to reset your password: ${resetLink}`,
    );

    res.json({ message: "Reset link sent to email" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/resetpassword/:token", async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({ message: "Password is required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters",
      });
    }

    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired token",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;

    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// admin routes

app.get("/admin/stats", async (req, res) => {
  try {
    const total = await Complaint.countDocuments();
    const pending = await Complaint.countDocuments({ status: "pending" });
    const resolved = await Complaint.countDocuments({ status: "completed" });

    res.json({
      total,
      pending,
      resolved,
    });
  } catch (err) {
    res.status(500).json({ message: "Error fetching stats" });
  }
});

// GET all pending complaints
app.get("/admin/complaints", async (req, res) => {
  try {
    const complaints = await Complaint.find({ status: "pending" })
      .populate("user", "username email contact");

    res.json(complaints);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error fetching complaints" });
  }
});

// Mark complaint completed
app.put("/admin/complaint/:id", async (req, res) => {
  try {
    await Complaint.findByIdAndUpdate(req.params.id, {
      status: "completed",
    });

    res.json({ message: "Complaint marked as completed" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error updating complaint" });
  }
});

// GET all users
app.get("/admin/users", async (req, res) => {
  try {
    const users = await User.find().select("-password"); // hide password
    res.json(users);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

// GET resolved complaints
app.get("/admin/resolved", async (req, res) => {
  try {
    const complaints = await Complaint.find({ status: "completed" })
      .populate("user", "username email contact");

    res.json(complaints);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error fetching resolved complaints" });
  }
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});
