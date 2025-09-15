const mongoose = require("mongoose");
const userSchema= new mongoose.Schema( {
  mobileNumber: {type: String, required : true},
  role: {type:String, enum:["customer" , "delivery"],required : true},
  createdAt: {type:Date, default: Date.now},
  lastLogin: {type:Date, default: Date.now}
 });
userSchema.index({ mobileNumber: 1, role: 1 }, { unique: true });
module.exports = mongoose.model("User", userSchema);