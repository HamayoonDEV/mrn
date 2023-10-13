import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_STRING, REFRESH_TOKEN_STRING } from "../config/index.js";
import RefreshToken from "../models/token.js";

class JwtServices {
  //signAccessToken
  static signAccessToken(payload, expiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN_STRING, { expiresIn: expiryTime });
  }
  //signRefreshToken
  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN_STRING, { expiresIn: expiryTime });
  }
  //verifyAccessToken
  static verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_TOKEN_STRING);
  }
  //verifyRefreshToken
  static verifyRefreshToken(token) {
    return jwt.verify(token, REFRESH_TOKEN_STRING);
  }
  //storeRefreshToken
  static async storeRefreshToken(userId, token) {
    try {
      const newToken = new RefreshToken({
        userId,
        token,
      });
      await newToken.save();
    } catch (error) {
      return error;
    }
  }
}

export default JwtServices;
