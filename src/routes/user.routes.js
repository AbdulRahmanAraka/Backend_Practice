import { Router } from "express";
import { loginUser, logoutUser, registerUser,refreshAccesToken } from "../controllers/user.controllers.js";
import {upload} from "../middlewares/multer.middleware.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";


const router= Router()

router.route("/register").post(
    //this is middleware
    upload.fields([
        {
            name: "avatar",
            maxCount:1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)

//secured route

router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccesToken)

export default router