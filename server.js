import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

import userRouter from "./routes/user.route.js";
import authRouter from "./routes/auth.route.js";
import listingRouter from "./routes/listing.route.js";

import {finalError} from "./middleware/finalError.js";

dotenv.config();

mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log("Connected to Atlas MongoDB");
}).catch((err) => {
    console.log(err);
})

const app = express();

app.use(express.json());
app.use(cookieParser());

app.listen(3000, () => {
    console.log("Server is running on port 3000");
})

app.use("/api/user", userRouter);
app.use("/api/auth", authRouter);
app.use("/api/listing", listingRouter);


app.use(finalError);