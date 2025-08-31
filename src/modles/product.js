const mongoose = require('mongoose')
const validator = require('validator')
const jwt = require('jsonwebtoken')
const { Schema } = mongoose

const productSchema = new Schema(
  {
    productName: {
      type: String,
      required: true
    },
    price: {
      type: Number,
      required: true
    },
    category: {
      type: String,
      required: true
    },
    discription: {
      type: String,
      required: true
    },
    url: {
      type: String,
      default:
        "https://png.pngtree.com/png-clipart/20221231/original/pngtree-cartoon-style-male-user-profile-icon-vector-illustraton-png-image_8836451.png"
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
      default: 4.0
    }
  },
  {
    timestamps: true
  }
)

const Product = mongoose.model('Product', productSchema, 'product')

module.exports = {
  Product
}
