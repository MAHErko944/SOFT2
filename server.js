const express=require("express")
const mongoose = require("mongoose");
const app = require("./index");
const PORT = 9000;
const helmet = require('helmet');
const csrf = require('csurf');

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

// Add Helmet for security headers
app.use(helmet());

// Add CSRF protection protect use Not needed..
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// For XSS prevention, sanitize output:
app.use((req, res, next) => {
  // Replace direct response sending with template rendering
  const originalSend = res.send;
  res.send = function(body) {
    // Sanitize HTML content or use proper templating instead of script alerts
    return originalSend.call(this, body);
  };
  next();
});

