import User from "../../models/user.model.js";
import bcryptjs from "bcryptjs";

import { AuthValidator } from "./validation.auth.js";

export const signup = async (req, res) => {
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
    res.status(400).json(error.message);
  }
};
