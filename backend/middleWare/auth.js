import JwtServices from "../services/JwtServices.js";
import User from "../models/user.js";

const auth = async (req, res, next) => {
  //fetching accesstoken ,refreshtoken
  const { accessToken, refreshToken } = req.cookies;

  if (!accessToken || !refreshToken) {
    const error = {
      status: 401,
      message: "unAuthorized!",
    };
    return next(error);
  }
  let id;
  try {
    id = JwtServices.verifyAccessToken(accessToken)._id;
  } catch (error) {
    return next(error);
  }
  let user;
  try {
    user = await User.findOne({ _id: id });
  } catch (error) {
    return next(error);
  }
  req.user;
  next();
};

export default auth;
