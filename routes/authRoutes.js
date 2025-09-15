const express = require('express');
const admin = require('../config/firebase');
const jwt = require("jsonwebtoken");
const User = require("../models/user");

const router = express.Router();
const jwt_secret = process.env.JWT_SECRET;

router.post("/request-otp",(req,res)=>{
    const  { mobileNumber, role } = req.body;
    if(!mobileNumber || !role ){
        return res.status(400).json({
            success: false,
            message: "mobile_number and role  are required"
        });
    }
    return res.json({
        success: true,
        message: `otp send to ${mobileNumber}`
    })
})

router.post("/verify-otp", async(req,res)=>{
    const  { mobileNumber, role ,otp } = req.body;
     if(!mobileNumber || !role || !otp ){
        return res.status(400).json({
            success: false,
            message: "mobile_number ,otp and role  are required"
        });
    }
    try{
        const decoded = await admin.auth().verifyIdToken(otp);

        if (decoded.phone_number !== mobileNumber){
           return res.status(401).json({ success: false, message: "invalid otp"});
        }
        let user = await User.findOne({ mobileNumber });

        if(!user){
            user = new User({ mobileNumber, role, createdAt: new Date(), lastLogin: new Date() });


        }else{
            user.lastLogin = new Date();
            user.role = role;
        }
        await user.save();
        const token = jwt.sign(
            {id: user._id, mobileNumber: user.mobileNumber, role: user.role},
            jwt_secret,
            { expiresIn:  process.env.JWT_EXPIRES_IN }

        )
    
    res.json({
        success: true,
        token,
        user:{
            id: user._id,
            mobileNumber: user.mobileNumber,
            role: user.role,
            createdAt : user.createdAt,
            lastLogin: user.lastLogin,
      },
    });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ success: false, message: "OTP verification failed" });
  }
});
      
router.post("/login", async (req, res) => {
    try {
        const { mobileNumber, role } = req.body;

        if (!mobileNumber || !role) {
            return res.status(400).json({
                success: false,
                message: "mobile_number and role are required"
            });
        }

        const user = await User.findOne({ mobileNumber, role });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found. Please register first using OTP verification."
            });
        }

        user.lastLogin = new Date();
        await user.save();
        const token = jwt.sign(
            {
                id: user._id,
                mobileNumber: user.mobileNumber,
                role: user.role
            },
            jwt_secret,
            { expiresIn: process.env.JWT_EXPIRES_IN  }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                mobileNumber: user.mobileNumber,
                role: user.role,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
            },
            message: "Login successful"
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
});

module.exports = router;
