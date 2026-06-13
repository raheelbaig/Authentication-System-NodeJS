import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";




export async function register(req, res) {
    try {
        const { username, email, password } = req.body ?? {};

        if (!username || !email || !password) {
            return res.status(400).json({
                message: "username, email and password are required",
                received: { username: !!username, email: !!email, password: !!password },
            })
        }

        const isAlreadyRegistered = await userModel.findOne({
            $or: [
                { username },
                { email }
            ]
        })

        if (isAlreadyRegistered) {
            return res.status(409).json({
                message: "Username or email already registered",
            })
        }

        const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

        const newUser = await userModel.create({
            username,
            email,
            password: hashedPassword,
        })

        const accessToken = jwt.sign({
            id: newUser._id,
        }, config.JWT_SECRET, { expiresIn: "15m" })

        const refreshToken = jwt.sign({
            id: newUser._id,
        }, config.JWT_SECRET, { expiresIn: "7d" })

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })

        res.status(201).json({
            message: "User registered successfully",
            user: newUser,
            accessToken,
        })
    } catch (error) {
        res.status(500).json({
            message: "Internal server error",
            error: error.message,
        })
    }
}

export async function getMe(req, res) {

    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        res.status(401).json({
            message: "Unauthorized",
        })
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    if (!user) {
        res.status(401).json({
            message: "Unauthorized",
        })
    }

    res.status(200).json({
        message: "User fetched successfully",
        user: {
            username: user.username,
            email: user.email,
        },
    })
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
        res.status(401).json({
            message: "Unauthorized",
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const accessToken = jwt.sign({
        id: decoded.id,
    }, config.JWT_SECRET, { expiresIn: "15m" })

    const newRefreshToken = jwt.sign({
        id: decoded.id,
    }, config.JWT_SECRET, { expiresIn: "7d" })

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    res.status(200).json({
        message: "Token refreshed successfully",
        accessToken,
    })
}