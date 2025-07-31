const mongoose = require('mongoose');


const dataBase= process.env.DB_URL

async function dbConnected(){
    // Connection of Clusters 
    await mongoose.connect(dataBase)
}

module.exports = {
   dbConnected
}