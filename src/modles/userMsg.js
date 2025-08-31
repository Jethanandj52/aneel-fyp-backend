 const mongoose = require('mongoose')
 const validator = require('validator')
 const jwt= require('jsonwebtoken')
 const {Schema} = mongoose

const msgSchema = new Schema(
    {
        fullName:{
            type: String,
            require: true,
            minLength: 3,
            maxLength: 20,
        },

         
        email:{
            type:String,
            
            required: true,
            lowercase:true,
            trim:true,
            validate(value){
                if(!validator.isEmail(value)){
                    throw new Error("Please write a correct way of email")
                }
            }
         },

            message:{
            type:String,
            
            required: true,
            lowercase:true,
            trim:true,
            
         },
        
        

       
         
    },
    {
        timestamps:true
    }
);

// The collection name can be specified as the third argument to mongoose.model
const UserMsg = mongoose.model('UserMsg', msgSchema,'message');
module.exports={
    UserMsg
} 