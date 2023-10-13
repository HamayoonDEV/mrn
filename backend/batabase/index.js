import { DATABASE_CONNECTION_STRING } from "../config/index.js";
import mongoose from "mongoose";

const connectDb = async () => {
  try {
    const con = await mongoose.connect(DATABASE_CONNECTION_STRING);
    console.log(`Database is connected to the host:${con.connection.host}`);
  } catch (error) {
    console.log(error);
  }
};
export default connectDb;
