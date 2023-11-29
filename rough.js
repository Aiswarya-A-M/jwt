const mysql = require("mysql2");
const express = require("express");
const dotEnv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
dotEnv.config();
const app = express();
app.use(express.json());
let refreshTokens = [];

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
      if (result.length === 0) {
        const sql = `INSERT INTO registration (fname,lname,email,password,phoneNumber) VALUES ("${fName}","${lName}","${email}","${password}","${phoneNumber}")`;
        connection.query(sql, (error, result) => {
          if (error) {
            return console.log(error);
          }
        });
        res.end("added to registration table");
      }
      return res.end("given mail id is already used");
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
    connection.query(sql, (error, result) => {
      if (error) {
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
          const user = { id: result[0].id };
          const accessToken = generateAccessToken(user);
          const refreshToken = jwt.sign(
            user,
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "3600s" }
          );
          refreshTokens.push(refreshToken);
          return res.json({
            accessToken: accessToken,
            refreshToken: refreshToken,
          });
        }
        return res.send("invalid password");
      });
    });
  } catch (error) {
    console.log(error);
  }
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) {
    res.send("no refresh token");
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.send("invalid refresh token");
  }
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    (error, result) => {
      console.log(result);
      const accessToken = generateAccessToken({
        userId: result.id,
      });
      res.send({ "new token": accessToken });
    }
  );
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "300s" });
}

app.get("/user/:id", authenticateToken, (req, res) => {
  try {
    const id = req.params.id;
    const sql = `SELECT * FROM registration WHERE id= ${id}`;
    connection.query(sql, (error, result) => {
      if (error) {
        return console.log(error);
      }
      if (result.length === 0) {
        return res.send("no user exist");
      }
      return res.json(result);
    });
  } catch (error) {
    console.log(error);
  }
});

app.put("/user/:id", authenticateToken, (req, res) => {
  try {
    const id = req.params.id;
    const sql = `SELECT * FROM registration WHERE id= ${id}`;
    connection.query(sql, (error, result) => {
      if (error) {
        return console.log(error);
      }
      if (result.length === 0) {
        return res.send("no user exist");
      }
      const sql = `UPDATE registration SET fname = "${req.body.fname}",lname = "${req.body.lname}" , phoneNumber = "${req.body.phoneNumber}" WHERE id=${id}`;
      connection.query(sql, (error, result) => {
        if (error) {
          return console.log(error);
        }
      });
      res.end("update details to registration table");
    });
  } catch (error) {
    console.log(error);
  }
});

app.delete("/user/:id", authenticateToken, (req, res) => {
  try {
    const id = req.params.id;
    const sql = `SELECT * FROM registration WHERE id= ${id}`;
    connection.query(sql, (error, result) => {
      if (error) {
        return console.log(error);
      }
      if (result.length === 0) {
        return res.send("no user exist");
      }
      const sql = `DELETE FROM registration  WHERE id=${id}`;
      connection.query(sql, (error, result) => {
        if (error) {
          return console.log(error);
        }
      });
      res.end("delete details from registration table");
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
    next();
  });
}

app.listen("3000", () => {
  console.log("server started on port 3000");
});
