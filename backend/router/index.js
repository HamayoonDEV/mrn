import express from "express";
import authController from "../controller/authController.js";
import auth from "../middleWare/auth.js";

const router = express.Router();

//authController endPoints
router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/logout", auth, authController.logout);
router.get("/refresh", authController.refresh);

export default router;
