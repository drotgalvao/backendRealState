import User from "../../models/user.model.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";

import { AuthValidator } from "./validation.auth.js";
import { errorHandler } from "../../utils/error.js";

export const signup = async (req, res, next) => {
  const { username, name, email, password, confirmPassword } = req.body;

  try {
    AuthValidator.areRequiredFieldsFilled(
      username,
      name,
      email,
      password,
      confirmPassword
    );
    AuthValidator.doPasswordsMatch(password, confirmPassword);
    AuthValidator.isStrongPassword(password);
    AuthValidator.isValidEmailFormat(email);
    await AuthValidator.isUsernameUnique(username, User);
    await AuthValidator.isEmailUnique(email, User);

    const hashedPassword = bcryptjs.hashSync(password, 10);

    const newUser = new User({
      username,
      name,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json("User created!");
  } catch (error) {
    next(errorHandler(400, error.message));
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return next(errorHandler(404, "User not found"));
    }

    const isPasswordCorrect = bcryptjs.compareSync(password, user.password);
    if (!isPasswordCorrect) {
      return next(errorHandler(400, "Wrong password"));
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    const { password: _, ...userWithoutPassword } = user.toObject();

    res
      .cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
      })
      .status(200)
      .json(userWithoutPassword);
  } catch (error) {
    next(error);
  }
};

export const google = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      const { password: _, ...userWithoutPassword } = user.toObject();
      res
        .cookie("token", token, {
          httpOnly: true,
          expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
        })
        .status(200)
        .json(userWithoutPassword);
    } else {
      const generatedPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
      const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);

      const newUser = new User({
        username: req.body.name.split(" ").join("").toLowerCase() + Math.random().toString(36).slice(-4),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        avatar: req.body.photo,
      });
      await newUser.save();
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
      const { password: _, ...userWithoutPassword } = newUser.toObject();
      res
        .cookie("token", token, {
          httpOnly: true,
          expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
        })
        .status(200)
        .json(userWithoutPassword);

    }
  } catch (error) {
    next(error);
  }
};

export const signout = async (req, res, next) => {
  try {
    res.clearCookie("token").status(200).json("User has been signed out!");
  } catch (error) {
    next(error);
  }
}
