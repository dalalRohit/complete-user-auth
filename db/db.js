require("dotenv").config();
const mongoose = require("mongoose");

const connectionParams = {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
};
const url =
  process.env.NODE_ENV === "dev" ? process.env.LOCAL_DB : process.env.PROD_DB;

mongoose
  .connect(url, connectionParams)
  .then(() => {
    console.log("Connected to database\n", url);
  })
  .catch((err) => {
    console.error(`Error connecting to the database. \n${err}`);
  });
