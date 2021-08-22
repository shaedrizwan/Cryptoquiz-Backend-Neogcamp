const mongoose = require('mongoose')
const Schema = mongoose.Schema


const userSchema = new Schema({
    firstname:{
        type:String,
        required:["First name required"]
    },
    lastname:{
        type:String,
        required:["Last name required"]
    },
    email:{
        type:String,
        require:["Email ID required"],
        unique:["Email ID already exists"]
    },
    password:{
        type:String,
        required:["Password required"]
    }
})

module.exports = mongoose.model('User',userSchema)