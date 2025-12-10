import { User } from '../models/userModel.js';

/**
 * 🔥 DAY-6: Authorization Middleware
 * 
 * Usage:
 * app.get('/admin/users', protect, allowRoles('admin'), getAllUsers)
 * app.delete('/admin/users/:id', protect, allowRoles('admin', 'manager'), deleteUser)
 * 
 * @param  {...string} allowedRoles - Roles that are allowed to access the route
 * @returns {Function} Express middleware
 */

export const allowRoles = (...allowedRoles) => {
    return async (req, res, next) => {
        try {
            // req.user is set by the protect middleware (contains user ID)
            if(!req.user){
                return res.status(401).json({
                    success: false,
                    error: "Authentication required"
                });
            }

            // Fetch user from database to get their role
            const user = await User.findById(req.user);
            
            if(!user){
                return res.status(404).json({
                    success: false,
                    error: "User not found"
                })
            }

            // Check if user's role is in the allowed roles
            if(!allowedRoles.includes(user.role)){
                return res.status(403).json({
                    success: false,
                    error: "Forbidden: You don't have permission to access this resource",
                    requiredRoles: allowedRoles,
                    yourRole: user.role
                });
            }

            // Attach user object to request for use in route handlers
            req.userRole = user.role;
            req.userObject = user;

            next();
        } catch (error) {
            res.status(500).json({
                success: false,
                error: "Authorization check failed",
                message: error.message
            });
        }
    };
};