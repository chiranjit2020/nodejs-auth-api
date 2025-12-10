import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import "../config/db.js";


const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 6,
        select: false // Don't return password by default
    },
    // 🔥 DAY-6: Add role field
    role: {
        type: String,
        enum: ['user', 'admin', 'manager'], // Only allow these values
        default: 'user' // Default role for new users
    },
    // 🔥 DAY-5 CHANGE: Array of refresh tokens (multi-device support)
    refreshTokens: [{
        token: {
            type: String,
            required: true
        },
        device: {
            type: String,
            default: 'unknown'
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }]

}, { timestamps: true })


// Hash password before saving  
userSchema.pre("save", async function () {
    // Only hash if password is modified
    if (!this.isModified("password")) return;
    this.password = await bcrypt.hash(this.password, 10);
});

export const User = mongoose.model("User", userSchema);