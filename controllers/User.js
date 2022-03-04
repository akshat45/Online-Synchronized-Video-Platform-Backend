import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import userModel from "../models/userSchema.js";


export const userLogin = (req, res, next) => {
    const { username, password } = req.body;

    // check for user exsistance and token sign
    userModel.findOne({ username: username })
        .then((data) => {
            if (data) {
                bcrypt.compare(password, data.password)
                    .then((check) => {
                        if (check) {
                            const token = jwt.sign({ email: data.email, _id: data._id, username: data.username }, process.env.hashtoken);
                            return res.status(200).json({ token, username: data.username, _id: data._id, message: "You are logged in successfully." });
                        }
                        else
                            throw new Err('Invalid Credentials.', 403);
                    })
                    .catch((err) => {
                        next(err);
                    });
            }
            else
                throw new Err("Username does not exist.", 403);
        })
        .catch((err) => {
            next(err);
        });
};

export const userSignup = async (req, res, next) => {
    const { name, email, username, password, confirmPassword } = req.body;

    // check duplicate username
    await userModel.findOne({ $or: [{ username }, { email }] })
        .then((data) => {
            if (data) {
                if (data.email == email)
                    throw new Err("Email entered is already registered with us.", 403);
                else if (data.username == username)
                    throw new Err("Username already exsist choose another one.", 403);

                if (password !== confirmPassword)
                    throw new Err("Password and Confirm Password don't match.", 403);
            }
        })
        .catch((err) => {
            next(err);
        });

    // hashing password and creating user
    bcrypt.hash(password, 4)
        .then((hash) => {
            userModel.create({ name, email, username, password: hash })
                .then((data) => {
                    const token = jwt.sign(
                        { email: data.email, _id: data._id, username: data.username },
                        process.env.hashtoken
                    );

                    return res.status(200).json({ token, username: data.username, _id: data._id, message: "You are signuped successfully." });
                })
                .catch((err) => {
                    next(err);
                });
        })
        .catch((err) => {
            next(err);
        });
};

