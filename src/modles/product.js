 const mongoose = require('mongoose')
 const validator = require('validator')
 const jwt= require('jsonwebtoken')
 const {Schema} = mongoose

const productSchema = new Schema(
    {
        productName:{
            type: String,
            require: true,
            
        },
        price:{
            type:Number,
            require:true
        },

        category:{
            type:String,
            require:true
        },

        discription:{
            type:String,
            require:true
        },

       
         url:{
                type : String,
                default:"https://png.pngtree.com/png-clipart/20221231/original/pngtree-cartoon-style-male-user-profile-icon-vector-illustraton-png-image_8836451.png",

                
         },

        
         
    },
    {
        timestamps:true
    }
);

// The collection name can be specified as the third argument to mongoose.model
const Product = mongoose.model('Product', productSchema, 'Product');
module.exports={
    Product
} 