import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { User } from '../models/userModel.js';

// Helper: Generate Tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { id: userId },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
        { id: userId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN } 
    );

    return { accessToken, refreshToken };
};

// 🔥 DAY-5: Register controller
// 🔥 DAY-6: Register with optional role
export const register = async (req, res) => {
    try {
        const { name, email, password, device = 'unknown', role } = req.body;

        const existingUser = await User.findOne({ email });
        if(existingUser){
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        // 🔥 Create user with role (defaults to "user" if not provided)
        const userData = { name, email, password };
        if(role && ['user', 'admin', 'manager'].includes(role)){
            userData.role = role;
        }


        const user = await User.create(userData);
        const { accessToken, refreshToken } = generateTokens(user._id);

        // 🔥 DAY-5: Add token to array (not overwrite)
        user.refreshTokens.push({
            token: refreshToken,
            device: device,
            createdAt: new Date()
        });

        await user.save();

        res.json({ 
            success: true, 
            token: accessToken, 
            refreshToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role // 🔥 Return role
            }
        });

    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// 🔥 DAY-5: Login controller
export const login = async (req, res) => {
    try {
        const { email, password, device = 'unknown' } = req.body;

        const user = await User.findOne({ email }).select('+password');
        if(!user){
            return res.status(400).json({ success: false, message: "Invalid email or password." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const { accessToken, refreshToken } = generateTokens(user._id);

        // 🔥 DAY-5: Add new token to array (allows multi-device login)
        user.refreshTokens.push({
            token: refreshToken,
            device: device,
            createdAt: new Date()
        });
        await user.save();

        res.json({ 
            success: true, 
            token: accessToken, 
            refreshToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role // 🔥 Return role
            } 
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
}

// Get current user (no changes needed)
export const getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user).select("-password");
        if(!user){
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// 🔥 DAY-5: Refresh token with ROTATION + THEFT DETECTION
export const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if(!refreshToken){
            return res.status(401).json({ success: false, error: "Refresh token required"});
        }

        // Step 1: Verify JWT
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if(!user){
            return res.status(401).json({ success: false, error: "User not found" });
        }

        // Step 2: 🔥 CRITICAL - Find token in array
        const tokenIndex = user.refreshTokens.findIndex(t => t.token === refreshToken);

        if(tokenIndex === -1){
            // 🚨 THEFT DETECTED: Valid JWT but not in DB
            console.log('🚨 TOKEN THEFT DETECTED for user:', user.email);
            
            //clear ALL tokens (logout everywhere)
            user.refreshTokens = [];
            await user.save();

            return res.status(401).json({
                success: false,
                error: "Token theft detected. All devices have been logged out. Please login again"
            });
        }

        // Step 3: 🔥 TOKEN ROTATION - Delete old token
        user.refreshTokens.splice(tokenIndex, 1);

        // Step 4: Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

        // Step 5: 🔥 Add new refresh token to array
        user.refreshTokens.push({
            token: newRefreshToken,
            device: user.refreshTokens[tokenIndex]?.device || 'unknown',
            createdAt: new Date()
        });

        await user.save();

        res.json({
            success: true,
            token: accessToken,
            refreshToken: newRefreshToken // 🔥 Return new refresh token
        });
    } catch (error) {
        return res.status(401).json({
            success: false,
            error: "Invalid or expired refresh token"
        });
    }
};

// 🔥 DAY-5: Logout (remove specific device token)
export const logout = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if(!refreshToken){
            return res.status(400).json({ success: false, error: "Refresh token required" });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if(!user){
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        // 🔥 Remove only the matching token (device-specific logout)
        user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
        await user.save();

        res.json({
            success: true,
            message: "Logged out successfully from this device"
        });
    } catch (error) {
        return res.status(401).json({ success: false, error: "Invalid refresh token" });
    }
}

// 🔥 DAY-5: Logout from ALL devices
export const logoutAll = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if(!refreshToken){
            return res.status(400).json({ success: false, error: "Refresh token required" });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);
        if(!user){
            return res.status(404).json({ success: false, error: "user not found" });
        }

        // 🔥 Clear ALL tokens
        user.refreshTokens = [];
        await user.save();

        res.json({
            success: true,
            message: "Logged out successfully from all devices"
        });

    } catch (error) {
        return res.status(401).json({ success: false, error: "invalid refresh token" });
    }
};

// 🔥 DAY-6: Admin-only endpoint - Get all users
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({}).select("-password -refreshTokens");
        res.json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
}

// 🔥 DAY-6: Admin-only endpoint - Delete user
export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findByIdAndDelete(userId);
        if(!user){
            return res.staus(404).json({ success: false, message: "user not found "});
        }

        res.json({
            success: true, 
            message: "User deleted successfully"
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
}



































/*
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { User } from '../models/userModel.js';

// Helper: Generate tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { id: userId }, 
        process.env.JWT_ACCESS_SECRET, 
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    const refreshToken = jwt.sign(
        { id: userId }, 
        process.env.JWT_REFRESH_SECRET, 
        { expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN }
    );
    
    return { accessToken, refreshToken };
};

// Register controller
export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }
        
        const user = await User.create({ name, email, password });
        const { accessToken, refreshToken } = generateTokens(user._id);
        
        user.refreshToken = refreshToken;
        await user.save();
        
        res.json({ success: true, token: accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Login controller
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email }).select("+password");
        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }
        
        const { accessToken, refreshToken } = generateTokens(user._id);
        
        user.refreshToken = refreshToken;
        await user.save();
        
        res.json({ success: true, token: accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Get current user
export const getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user).select("-password");
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Refresh token
export const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(401).json({ success: false, error: "Refresh token required" });
        }
        
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id).select("+refreshToken");
        
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ success: false, error: "Invalid refresh token" });
        }
        
        const newAccessToken = jwt.sign(
            { id: decoded.id }, 
            process.env.JWT_ACCESS_SECRET, 
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );
        
        res.json({ success: true, token: newAccessToken });
    } catch (error) {
        return res.status(401).json({ success: false, error: "Invalid or expired refresh token" });
    }
};

// Logout
export const logout = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(400).json({ success: false, error: "Refresh token required" });
        }
        
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);
        
        if (!user) {
            return res.status(404).json({ success: false, error: "User not found" });
        }
        
        user.refreshToken = null;
        await user.save();
        
        res.json({ success: true, message: "Logged out successfully from all devices" });
    } catch (error) {
        return res.status(401).json({ success: false, error: "Invalid refresh token" });
    }
};
*/