const express = require('express')
const router = express.Router()
const User = require('../models/user.model')
const bcrypt = require('bcryptjs')
const {checkAuth} = require('../middlewares/auth.middleware')
const jwt = require('jsonwebtoken')

router.route('/')
    .get((req,res)=>{
        res.json({msg:"User route"})
    })


router.route('/signup')
    .post(async(req,res)=>{
        try{
            const user = req.body
            const salt = await bcrypt.genSalt(10)
            const hashedPassword = await bcrypt.hash(user.password,salt)
            user.password = hashedPassword
            const newUser = new User(user)
            addedUser = await newUser.save()
            res.json({success:true,newUser})
        }catch(err){
            res.json({success:false,error:err.message})
        }
    })

router.use(checkAuth)
router.route('/login')
    .post((req,res)=>{
        const user = req.user
        const token = jwt.sign({userId:user._id},process.env.TOKEN_SECRET,{expiresIn: '24h'})
        res.json({success:true,message:"Login successful",token})
    })
    .get((req,res)=>{
        res.send("Login route")
    })

module.exports = router