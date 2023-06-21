import { User } from "../models/user.js";
import jwt from "jsonwebtoken";

export const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token)
    return res.status(404).json({
      success: false,
      message: "Login First",
    });

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
    //here instead of using any var we are just giving value in req.user only so that
    // it is univarsal and can be accesed in the fn where is authenticated is used
  req.user = await User.findById(decoded._id);
  next();
};
