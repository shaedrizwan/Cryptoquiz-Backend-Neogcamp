const User = require('../models/user.model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const checkAuth = async(req,res,next) =>{
    try{
        const {email,password} = req.body
        user = await User.findOne({email})
        if(user){
            isPasswordValid = await bcrypt.compare(password,user.password)
            if(isPasswordValid){
                req.user = user
                return next()
            }else{
                return res.status(403).json({success:false,message:"Authentication failed: Incorrect password"})
            }
        }else{
            return res.status(404).json({success:false,message:"User does not exist"})
        }
    }catch(err){
        return res.status(500).json({success:false,error:err.message})
    }
}

const verifyAuth = (req,res,next)=>{
    const token = req.headers.authorization
    try{
        const decoded = jwt.verify(token,process.env.TOKEN_SECRET)
        req.user = decoded.userId
        return next()
    }catch(err){
        return res.status(401).json({success:false,message:"Token not valid! Please login again"})
    }
}

module.exports = {checkAuth,verifyAuth}