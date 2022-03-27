const express = require('express')
const app = express()
const cors = require('cors')
const {initializeDB} = require('./database/db.connect')
const userRoute = require('./routes/user.route')
const quizRoute = require('./routes/quiz.route')

initializeDB()
app.use(cors())
app.use(express.json())

app.use('/user',userRoute)
app.use('/quiz',quizRoute)


app.get('/', (req, res) => {
  res.send('CryptoQuiz app backend built by Shahid Rizwan!')
})




// 404 Route (Should always be at the end)
app.use((req,res)=>{
  res.status(404).json({success:false,errorMessage:"404 Not Found"})
})

app.listen(process.env.PORT, () => {
  console.log(`Example app listening at http://localhost:${process.env.PORT}`)
})