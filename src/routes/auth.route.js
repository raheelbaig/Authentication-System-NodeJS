import router from "express";
import * as authController from "../controllers/auth.controller.js";

const authRouter = router();

authRouter.post("/register", authController.register);

authRouter.get("/get-me", authController.getMe)

authRouter.get("/refresh-token", authController.refreshToken);

export default authRouter;