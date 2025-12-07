import jwt from 'jsonwebtoken';

// Generate access token
export const generateAccessToken = (userId) => {
    return jwt.sign(
        { id: userId }, 
        process.env.JWT_ACCESS_SECRET, 
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );
};

// Generate refresh token
export const generateRefreshToken = (userId) => {
    return jwt.sign(
        { id: userId }, 
        process.env.JWT_REFRESH_SECRET, 
        { expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN }
    );
};

// Store refresh token in DB
export const storeRefreshToken = async (user, token) => {
    user.refreshToken = token;
    await user.save();
};

// Send success response with tokens
export const sendTokenResponse = (res, accessToken, refreshToken) => {
    res.json({ 
        success: true, 
        token: accessToken,
        refreshToken: refreshToken
    });
};