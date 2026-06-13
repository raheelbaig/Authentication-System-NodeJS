import mongoose from 'mongoose';


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required" ],
        unique: [true, "Username must be unique" ],
    },
    email: {
        type: String,
        required: [true, "Email is required" ],
        unique: [true, "Email must be unique" ],
    },
    password: {
        type: String,
        required: [true, "Password is required" ],
        minlength: [8, "Password must be at least 8 characters long" ],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
}, { timestamps: true });

const userModel = mongoose.model("users", userSchema);

export default userModel;