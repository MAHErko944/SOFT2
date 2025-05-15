const express=require("express")
const mongoose = require("mongoose");
const app = require("./index");
const PORT = 9000;

app.use(express.json()); // to parse JSON bodies
app.use(express.urlencoded({ extended: true }));

require("dotenv").config();

/* Connecting to the database and then starting the server. */
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
  })
  .catch((err) => {
    console.log(err);
  });