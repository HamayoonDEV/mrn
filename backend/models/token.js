import mongoose from "mongoose";

const { Schema } = mongoose;

const tokenSchema = new Schema(
  {
    userId: { type: mongoose.SchemaTypes.ObjectId, ref: "User" },
    token: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("RefreshToken", tokenSchema, "token");
