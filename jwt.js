const mysql = require("mysql2");
const express = require("express");
const dotEnv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
dotEnv.config();
const app = express();
app.use(express.json());

const connection = mysql.createConnection({
  host: process.env.host,
  user: process.env.user,
  password: process.env.password,
  database: process.env.database,
});

connection.connect((error) => {
  if (error) {
    console.error("Error connecting to MySQL database:", error);
  } else {
    console.log("Connected to MySQL database!");
  }
});

app.get("/", (req, res) => {
  res.json({
    message: "success",
  });
});

app.post("/register", (req, res) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    req.body.password = bcrypt.hashSync(req.body.password, salt);
    const fName = req.body.fname;
    const lName = req.body.lname;
    const email = req.body.email;
    const password = req.body.password;
    const phoneNumber = req.body.phoneNumber;
    const checkingQuery = `SELECT email FROM registration WHERE email="${email}"`;
    connection.query(checkingQuery, (error, result) => {
      if (result.length !== 0) {
        return res.end("given mail id is already used");
      }
    });
    const sql = `INSERT INTO registration (fname,lname,email,password,phoneNumber) VALUES ("${fName}","${lName}","${email}","${password}","${phoneNumber}")`;
    connection.query(sql, function (error, result) {
      if (error) {
        return console.log(error);
      }
      res.end("added to registration table");
    });
  } catch (error) {
    console.log(error);
  }
});

app.get("/user/:id", authenticateToken, (req, res) => {
  try {
    const id = req.params.id;
    const sql = `SELECT * FROM registration WHERE id= ${id}`;
    connection.query(sql, function (error, result) {
      if (error) {
        return console.log(error);
      }
      res.json(result);
    });
  } catch (error) {
    console.log(error);
  }
});

app.post("/login", (req, res) => {
  try {
    const userName = req.body.email;
    const providedPassword = req.body.password;
    const sql = `SELECT id,password FROM registration WHERE email="${userName}"`;
    connection.query(sql, function (error, result) {
      if (error) {
        console.log("login query", error);
        return res.json({ message: "internal server error" });
      }
      if (result.length === 0) {
        return res.send("invalid mail id ");
      }

      const storedPassword = result[0].password;
      bcrypt.compare(providedPassword, storedPassword, (error, isMatch) => {
        if (error) {
          console.log(error);
        }
        if (isMatch) {
          const user = { userName: userName, password: storedPassword };
          const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
          return res.json({ accessToken: accessToken });
        }
        return res.send("invalid password");
      });
    });
  } catch (error) {
    console.log(error);
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  console.log(authHeader);
  const token = authHeader.split(" ")[1];
  console.log(token);
  if (!token) {
    return res.sendStatus(403);
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, result) => {
    if (error) {
      return res.end("invalid token");
    }
    req.user = result;
    next();
  });
}
app.listen("3000", () => {
  console.log("server started on port 3000");
});
