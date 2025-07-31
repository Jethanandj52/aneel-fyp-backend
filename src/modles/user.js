 const mongoose = require('mongoose')
 const validator = require('validator')
 const jwt= require('jsonwebtoken')
 const {Schema} = mongoose

const userSchema = new Schema(
    {
        firstName:{
            type: String,
            require: true,
            minLength: 3,
            maxLength: 20,
        },

         lastName:{
            type: String,
            required: true,
            minLength: 3,
            maxLength: 20,
        },
        email:{
            type:String,
            unique:true,
            required: true,
            lowercase:true,
            trim:true,
            validate(value){
                if(!validator.isEmail(value)){
                    throw new Error("Please write a correct way of email")
                }
            }
         },
         password:{
            type:String,
            require:true,
            validate(value){
                if(!validator.isStrongPassword(value)){
                    throw new Error ("Please Enter Strong Passowd")
                }
            }
         },
         url:{
                type : String,
                default:"https://png.pngtree.com/png-clipart/20221231/original/pngtree-cartoon-style-male-user-profile-icon-vector-illustraton-png-image_8836451.png",

                validate(value){
                    if(!validator.isURL(value)){
                        throw new Error("Please enter url of image")
                    }
                }
         },

         isActive:{
                type:Boolean,
                default:false
         }
         
    },
    {
        timestamps:true
    }
);

// The collection name can be specified as the third argument to mongoose.model
const User = mongoose.model('User', userSchema, 'users');
module.exports={
    User
} 