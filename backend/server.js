import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import dotenv from 'dotenv';
import cors from 'cors';
import crypto from 'crypto';

import connectDB from './db/db.js';  // Ensure the correct file extension (.js)
import authRoute from './routes/auth.route.js';
import User from './models/user.model.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/auth", authRoute);

app.get("/", (req, res) => {
    res.send("Server is running...");
});

app.get("/profile", async (req, res) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access Denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(verified.id).select("-password");
        res.json(user);
    } catch (err) {
        res.status(400).json({ error: "Invalid Token" });
    }
});

// Ensure .env is loaded before hashing
console.log(crypto.createHash('sha256').update(process.env.JWT_SECRET || "").digest('hex'));

(async () => {
        await connectDB();
})();
// connectDB();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
