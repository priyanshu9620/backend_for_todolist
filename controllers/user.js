import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import { sendCookie } from "../utils/features.js";
import ErrorHandler from "../middlewares/error.js";

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    //this +password is used as in schema u wrote password select fasle so specifically selecting here se that we can use that in ismatch 
    const user = await User.findOne({ email }).select("+password");
    //here we have used const user as there is only one user with this email and password 
    if (!user) return next(new ErrorHandler("Invalid Email or Password", 400));

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return next(new ErrorHandler("Invalid Email or Password", 400));

    sendCookie(user, res, `Welcome back, ${user.name}`, 200);
  }
  catch (error) {
    next(error);
  }
};

export const register = async (req, res,next) => {
  try {
    const { name, email, password } = req.body;
    
    //here we have used let user becuase there is not one user so const will save just single 
    let user = await User.findOne({ email });

    if (user) return next(new ErrorHandler("User Already Exist", 400));

    const hashedPassword = await bcrypt.hash(password, 10);

    user = await User.create({ name, email, password: hashedPassword });

    sendCookie(user, res, "Registered Successfully", 201);
  } catch (error) {
    next(error);
  }
};

//abhi we made such a temporary fn for user data to be reflected in postman just sending req.user 
export const getMyProfile = (req, res) => {
  res.status(200).json({
    success: true,
    //this req.user came from isauthenticated fn.
    user: req.user,
  });
};

export const logout = (req, res) => {
  res
    .status(200)
    //emptying the token means clearing the cookie while logout imp step
    .cookie("token", "", {
      expires: new Date(Date.now()),
      sameSite: process.env.NODE_ENV === "Development" ? "lax" : "none",
      secure: process.env.NODE_ENV === "Development" ? false : true,
    })
    .json({
      success: true,
      user: req.user,
    });
};
