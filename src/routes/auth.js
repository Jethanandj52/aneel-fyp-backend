const express= require('express')
const routes= express.Router()
const {User}= require('../modles/user')

const bcrypt = require('bcrypt')
const jwt =require('jsonwebtoken')
const validator = require('validator')
// const cookieParser =require('cookie-parser')
const nodemailer = require('nodemailer')
const { userAuth } = require('../middleware/Verify')

// const round= process.env.ROUND
const secretKey= process.env.SECRET_KEY

routes.post('/signup',async(req,res)=>{
    try {
       const {firstName,lastName,email,password}= req.body

       if(!firstName && lastName){
        throw new Error("Please Fill All Filed")
       } else if(!validator.isEmail(email)){
        throw new Error("Please enter valid email")
        
       } else if(!validator.isStrongPassword(password)){
        throw new Error("Please Enter Strong Password")

       }

       const hasedPassword= await bcrypt.hash(password,10)


       const user=await User({
        firstName,
        lastName,
        email,
        password:hasedPassword
       })

       user.save()

       const token = await jwt.sign({id:user._id},secretKey,{expiresIn:'1d'})
       res.cookie("token",token,{
       expires:  new Date(Date.now() + 60 * 10000),
       })
       res.send("User added successfully", User.email)
    } catch (error) {
        res.status(400).send("Error"+error.message)
    }

   
})

routes.post('/login',async(req,res)=>{
     try {

       const {email,password}= req.body
       
       const user = await  User.findOne({email})

       
       
       if(!user){
           throw new Error("user not found")
        }
        const validPassword= await bcrypt.compare(password,user.password)
        
        if(!validPassword){
            
            
            throw new Error("data invailid")
        }
        const token = await jwt.sign({id:user._id},secretKey,{expiresIn:'1d'})
        res.cookie("token",token,{
        expires:  new Date(Date.now() + 60 * 10000),
        })

       
        
        

         user.isActive = true;
            await user.save();
            res.send("successfully login")
     } catch (error) {
        res.status(400).send("Error"+error.message)
        
     }
})

const resetPasswordLink= process.env.RESET_LINK
const emailService= process.env.SERVICE
const myEmail= process.env.MY_EMAIL
const passKey= process.env.PASS_KEY

routes.post('/forget-password',async(req,res)=>{
    try {
             const {email}=req.body

             const user = await User.findOne({email})
             if(!user){
                throw new Error("User not found")
             }

                const token = jwt.sign({ id: user._id },secretKey, { expiresIn: '10m' });
             const resetLink = `${resetPasswordLink}/${token}`; // 🔁 FRONTEND LINK
             
                     // ✅ Send Email via Nodemailer
                     const transporter = nodemailer.createTransport({
                         service: emailService,
                         auth: {
                             user: myEmail, // 👈 your email
                             pass: passKey     // 👈 appRouter password from Gmail
                         }
                     });
                     const mailOptions = {
                         from: 'APIverse <your-email@gmail.com>',
                         to: email,
                         subject: 'Reset Your Password - APIverse',
                         html: `<p>Click the link below to reset your password:</p>
                                <a href="${resetLink}">${resetLink}</a>
                                <p>This link expires in 10 minutes.</p>`
                     };
             
                     await transporter.sendMail(mailOptions);
                     res.send({ message: "Password reset link sent to your email" });
 
    } catch (error) {
        res.status(400).send("Error"+error.message)
        
    }

})


 // path adjust kro if needed
routes.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

 

    const decoded = jwt.verify(token, secretKey);
   

    const user = await User.findById(decoded.id);
    if (!user) throw new Error("Invalid user");

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.send({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Password reset error:", error.message);
    res.status(400).send("Error: " + error.message);
  }
});


routes.post('/logout', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');

    user.isActive = false;
    await user.save();

    res.clearCookie('token'); // optional if you set cookies
    res.send({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(400).send('Error: ' + error.message);
  }
});

routes.get('/users', async (req, res) => {
  const users = await User.find();
  res.json({ users });
});

// DELETE specific user
routes.delete('/users/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ msg: 'User deleted' });
});
module.exports={
    routes
}