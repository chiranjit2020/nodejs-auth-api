import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();

mongoose.connect(process.env.MONGO_URI, {
    dbName: "auth_api"
})
.then(() => console.log("MongoDb connected!"))
.catch(err => {
    console.error("MomgoDB connection error", err)
    process.exit(1);
})