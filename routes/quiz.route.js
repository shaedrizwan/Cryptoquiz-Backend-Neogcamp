const express = require('express');
const { verifyAuth } = require('../middlewares/auth.middleware');
const router = express.Router();
const Quiz = require('../models/quiz.model')

router.route('/')
    .get(async(req,res)=>{
        const quizData = await Quiz.find({})
        res.json({success:true,quizData})
    })


router.route('/leaderboard')
    .post(async (req,res)=>{
        try{
            const {id} = req.body
            const quiz = await Quiz.findById(id).populate('leaderboard.user')
            const leaderboard = quiz.leaderboard.sort((a,b)=>b.score-a.score)
            leaderboard.map(standing => {
                standing.user.password = undefined
                standing.user.__v = undefined
            })
            res.json({success:true,leaderboard})
        }catch(err){
            res.json({success:false,error:err.message})
        }
    })

router.use(verifyAuth)
router.route('/add')
    .post(async(req,res)=>{
        try{
            const quiz = req.body;
            const newQuiz = new Quiz(quiz)
            addedQuiz = await newQuiz.save()
            res.json({success:true,addedQuiz})
        }catch(err){
            res.json({success:false,error:err.message})
        }
    })

router.route('/addToLeaderboard')
    .post(async(req,res)=>{
        try{
            const userId = req.user;
            const {score,quizId} = req.body;
            quiz = await Quiz.findById(quizId)
            updatedQuiz = {...quiz,leaderboard:quiz.leaderboard.push({user:userId,score})}
            updatedLeaderboard = await quiz.save()
            res.json({success:true,updatedLeaderboard:quiz.leaderboard})
        }catch(err){
            res.json({success:false,error:err.message})
        }
    })

module.exports = router