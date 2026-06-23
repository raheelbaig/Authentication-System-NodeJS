import router from "express";
import * as authController from "../controllers/auth.controller.js";

const authRouter = router();

authRouter.post("/register", authController.register);

authRouter.post("/login", authController.login);

authRouter.get("/get-me", authController.getMe)

authRouter.get("/refresh-token", authController.refreshToken);

authRouter.post("/logout", authController.logout);

authRouter.post("/logout-all", authController.logoutAll);

export default authRouter;