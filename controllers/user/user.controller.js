import bcryptjs from "bcryptjs";
import User from "../../models/user.model.js";
import { errorHandler } from "../../utils/errorHandler.js";
import Listing from "../../models/listing.model.js";

export const test = (req, res) => {
  res.send("Api route is working!");
};

export const updateUser = async (req, res, next) => {
  if (req.user.id !== req.params.id) {
    return next(errorHandler(401, "You are not authorized"));
  }

  try {
    if (req.body.password) {
      req.body.password = bcryptjs.hashSync(req.body.password, 10);
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          username: req.body.username,
          name: req.body.name,
          email: req.body.email,
          password: req.body.password,
          avatar: req.body.avatar,
        },
      },
      { new: true }
    );

    const { password, ...withoutPassword } = updatedUser._doc;
    res.status(200).json(withoutPassword);
  } catch (error) {
    next(error);
  }
  next();
};

export const deleteUser = async (req, res, next) => {
  if (req.user.id !== req.params.id) {
    return next(errorHandler(401, "You are not authorized"));
  }

  try {
    await User.findByIdAndDelete(req.params.id);
    res.clearCookie("token").status(200).json("User has been deleted!");
  } catch (error) {
    next(error);
  }
};

export const getUserListings = async (req, res, next) => {
  if (req.user.id === req.params.id) {
    try {
      const listing = await Listing.find({ userRef: req.params.id });
      res.status(200).json(listing);
    } catch (error) {
      next(error);
    }
  } else {
    return next(errorHandler(401, "You are not authorized"));
  }
};

export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return next(errorHandler(404, "User not found"));
    }

    const { password, ...withoutPassword } = user._doc;

    res.status(200).json(withoutPassword);
  } catch (error) {
    next(error);
  }
};
