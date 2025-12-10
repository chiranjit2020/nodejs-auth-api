import { protect } from "./src/middlewares/auth.js";
import { allowRoles } from './src/middlewares/authorize.js';
import { 
    register, 
    login, 
    getMe, 
    refreshToken, 
    logout, 
    logoutAll,
    getAllUsers,
    deleteUser
} from './src/controllers/authController.js';

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import morgan from 'morgan';

import dotenv from 'dotenv';
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS Configuration - IMPORTANT for preflight requests
const corsOptions = {
    origin: 'http://127.0.0.1:5500', // Your frontend URL
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

// Middleware
app.use(cors(corsOptions)); // Must be before routes
app.use(bodyParser.json());
app.use(morgan('dev'));

// 🔥 DAY-5 ROUTES
// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================
app.post('/api/users/register', register);
app.post('/api/users/login', login);

// ============================================
// AUTHENTICATED ROUTES (Require login)
// ============================================
app.get('/api/users/me', protect, getMe);
app.post('/api/users/refresh', refreshToken);
app.post('/api/users/logout', logout); // Logout from current device
app.post('/api/users/logout-all', logoutAll); // Logout from all devices

// ============================================
// 🔥 DAY-6: ADMIN-ONLY ROUTES
// ============================================
// Get all users - Only admins can access
app.get('/api/admin/users', 
    protect,                // Must be logged in
    allowRoles('admin'),    // Must be admin
    getAllUsers
);

// Delete user - Only admins can access
app.delete('/app/admin/users/:userId',
    protect,                // Must be logged in
    allowRoles('admin'),    // Must be admin
    deleteUser
);

// ============================================
// 🔥 DAY-6: MULTI-ROLE ROUTES
// ============================================
// Example: Both admin and manager can access
app.get('/api/reports/sales',
    protect,
    allowRoles('admin', 'manager'),     // Admin OR Manager
    (req, res) => {
        res.json({
            success: true,
            message: "Sales report data",
            accessedBy: req.userRole
        });
    }
);

// ============================================
// 🔥 DAY-6: USER-ONLY ROUTES
// ============================================
// Example: Only regular users (not admins)
app.post('/api/users/feedback',
    protect,
    allowRoles('user'),
    (req, res) => {
        res.json({
            success: true,
            message: "feedback submitted"
        });
    }
)

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});





// Register - Returns access token only
/*
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        // Create user (password will be hashed by pre-save hook)
        const user = await User.create({ name, email, password });

        // 🔥 Generate access token
        const accessToken = jwt.sign(
            { id: user._id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        // 🔥 Generate refresh token
        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN }
        );

        // 🔥 CRITICAL: Store refresh token in DB
        user.refreshToken = refreshToken;
        await user.save();

        res.json({
            success: true,
            token: accessToken,
            refreshToken: refreshToken
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});
*/
// ============================================
// 🔥 DAY-4: LOGIN - Store refresh token in DB
// ============================================
/*
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Get user with password field
        const user = await User.findOne({ email }).select("+password");

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        // Generate ACCESS token (short-lived: 1 minute)
        const accessToken = jwt.sign(
            { id: user._id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        // Generate REFRESH token (long-lived: 7 days)
        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN }
        );

        // 🔥 CRITICAL: Store refresh token in DB (overwrites old one)
        user.refreshToken = refreshToken;
        await user.save();

        res.json({
            success: true,
            token: accessToken,      // Access token for API calls
            refreshToken: refreshToken  // Refresh token to get new access tokens
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});
*/
// Get current user - Uses access token via protect middleware
/*
app.get('/api/users/me', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user).select("-password");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});
*/
// ============================================
// 🔥 DAY-4: REFRESH - Verify token matches DB
// ============================================
/*
app.post("/api/users/refresh", async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ success: false, error: "Refresh token required" });
        }

        // Step 1: Verify the REFRESH token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Step 2: 🔥 CRITICAL - Check if token matches DB
        const user = await User.findById(decoded.id).select("+refreshToken");

        if(!user){
            return refreshToken.status(401).json({ success: false, error: "User not found" });
        }

        // 🔥 THIS IS THE KEY SECURITY CHECK
        if(user.refreshToken !== refreshToken){
            // Token is valid JWT but doesn't match DB = STOLEN TOKEN

            return res.status(401).json({
                success: false,
                error: "Invalid refresh token - token mismatch"
            });
        }


        // Step 3: Generate new ACCESS token
        const newAccessToken = jwt.sign(
            { id: decoded.id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            success: true,
            token: newAccessToken
        });
    } catch (error) {
        return res.status(401).json({
            success: false,
            error: "Invalid or expired refresh token"
        });
    }
});
*/
// ==============================================
// 🔥 DAY-4: LOGOUT - Clear refresh token from DB
// ==============================================
/*
app.post("/api/users/logout", async(req, res) => {
    try {
        const { refreshToken } = req.body;

        if(!refreshToken){
            return res.status(400).json({ success: false, error: "Refresh token required" });
        }

        // Verify and decode the token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Find the user and clear their refresh token
        const user = await User.findById(decoded.id);

        if(!user){
            return res.status(404).json({ succcess: false, error: "User not found" });
        }

        // 🔥 CRITICAL: Clear refresh token from DB
        user.refreshToken = null;
        await user.save();

        res.json({
            success: true,
            message: "Logged out successfully from all devices"
        });
    } catch (error) {
        return res.status(401).json({
            succes: false,
            error: "Invalid refresh token"
        });
    }
});
*/
