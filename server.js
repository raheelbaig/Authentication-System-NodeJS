import app from "./src/app.js";
import connectDB from "./src/config/database.js";
import authRouter from "./src/routes/auth.route.js";

connectDB();

app.use("/api/auth", authRouter);

app.listen(3000, ()=> {
    console.log("Server is running on port 3000");
})