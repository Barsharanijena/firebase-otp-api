const jwt = require('jsonwebtoken');
const User = require('../models/user');

const jwt_secret = process.env.JWT_SECRET;

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token is required'
            });
        }

        const decoded = jwt.verify(token, jwt_secret);
        
     
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }


        req.user = {
            id: decoded.id,
            mobileNumber: decoded.mobileNumber,
            role: decoded.role
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token has expired'
            });
        }
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }

        return res.status(500).json({
            success: false,
            message: 'Token verification failed'
        });
    }
};


const authorizeRole = (allowedRoles) => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            const userRole = req.user.role;
            const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

            if (!roles.includes(userRole)) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required role(s): ${roles.join(', ')}`
                });
            }

            next();
        } catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed'
            });
        }
    };
};

const isCustomer = authorizeRole('customer');


const isDelivery = authorizeRole('delivery');


const isCustomerOrDelivery = authorizeRole(['customer', 'delivery']);

module.exports = {
    authenticateToken,
    authorizeRole,
    isCustomer,
    isDelivery,
    isCustomerOrDelivery
};