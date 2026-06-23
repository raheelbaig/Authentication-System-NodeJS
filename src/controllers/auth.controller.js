import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";




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

        const refreshToken = jwt.sign({
            id: newUser._id,
        }, config.JWT_SECRET, { expiresIn: "7d" })

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

        const session = await sessionModel.create({
            user: newUser._id,
            userAgent: req.headers["user-agent"],
            ip: req.ip,
            refreshTokenHash,
        })

        const accessToken = jwt.sign({
            id: newUser._id,
            sessionId: session._id,
        }, config.JWT_SECRET, { expiresIn: "15m" })


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

export async function login(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required",
            received: { email: !!email, password: !!password },
        })
    }

    const user = await userModel.findOne({ email });

    if (!user) {
        return res.status(401).json({
            message: "Invalid email!",
        })
    }

    const isPasswordCorrect = crypto.createHash("sha256").update(password).digest("hex") === user.password;

    if (!isPasswordCorrect) {
        return res.status(401).json({
            message: "Invalid password!",
        })
    }
    
    const refreshToken = jwt.sign({
        id: user._id,
    }, config.JWT_SECRET, { expiresIn: "7d" })

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    
    const session = await sessionModel.create({
        user: user._id,
        userAgent: req.headers["user-agent"],
        ip: req.ip,
        refreshTokenHash,
    })
    
    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id,
    }, config.JWT_SECRET, { expiresIn: "15m" })
    
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })
    
    res.status(200).json({
        message: "Logged in successfully",
        user: user,
        accessToken,
    })
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

    const session = await sessionModel.findOne({
        refreshTokenHash: crypto.createHash("sha256").update(refreshToken).digest("hex"),
        revoked: false,
    })

    if (!session) {
        res.status(401).json({
            message: "Invalid refresh token",
        })
    }

    const accessToken = jwt.sign({
        id: decoded.id,
    }, config.JWT_SECRET, { expiresIn: "15m" })

    const newRefreshToken = jwt.sign({
        id: decoded.id,
    }, config.JWT_SECRET, { expiresIn: "7d" })

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();

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

export async function logout(req, res) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token is required",
        })
    }

    const session = await sessionModel.findOne({
        refreshTokenHash: crypto.createHash("sha256").update(refreshToken).digest("hex"),
        revoked: false,
    })

    if (!session) {
        return res.status(401).json({
            message: "Unauthorized",
        })
    }

    session.revoked = true;
    await session.save();

    res.clearCookie("refreshToken");
    res.status(200).json({
        message: "Logged out successfully",
    })
}

export async function logoutAll(req, res) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token is required",
        })
    }


    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const sessions = await sessionModel.find({
        user: decoded.id,
        revoked: false,
    })

    for (const session of sessions) {
        session.revoked = true;
        await session.save();
    }

    res.clearCookie("refreshToken");
    res.status(200).json({
        message: "Logged out from all devices successfully",
    })
}