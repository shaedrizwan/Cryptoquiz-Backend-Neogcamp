const mongoose = require('mongoose')
const Schema = mongoose.Schema
const User = require('./user.model')

const quizSchema = new Schema({
    name:{
        type:String,
        required:["Quiz name required"]
    },
    totalQuestions:{
        type:Number,
        required:["Number of questions required"]
    },
    description:{
        type:String,
        required:["Description required"]
    },
    questions:[
        {
            question:String,
            options:[{
                option:String,
                isRight:Boolean
            }]
        }
    ],
    leaderboard:[{
        user:{type:mongoose.Types.ObjectId,ref:User},
        score:Number
    }]
})

module.exports = mongoose.model('Quiz',quizSchema)