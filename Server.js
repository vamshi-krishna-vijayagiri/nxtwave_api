// server.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(cors());
app.use(express.json());
const port = 5000;

// Create MySQL connection
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});


connection.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL database');
});



// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('MySQL connection failed:', err.stack);
    return;
  }
  console.log('Connected to MySQL Database');
});


app.post('/user-register', (req, res) => {
  const { name, email, password, company, age, dob } = req.body;

  // Check if the email already exists
  const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error during email check' });
    }

    if (results.length > 0) {
      return res.json({ message: 'Email already exists' });
    }

    // Hash the password
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error hashing password' });
      }

      const insertQuery = `
        INSERT INTO users (name, email, password, company, age, dob)
        VALUES (?, ?, ?, ?, ?, ?)
      `;

      db.query(insertQuery, [name, email, hashedPassword, company, age, dob], (err, results) => {
        if (err) {
          return res.status(500).json({ message: 'Database error during insertion' });
        }

        res.json({ message: 'Success', userId: results.insertId });
      });
    });
  });
});

app.post('/user-login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const loginQuery = 'SELECT id, password FROM users WHERE email = ?';

  db.query(loginQuery, [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid Credentials' });
    }

    const { id, password: hashedPassword } = results[0];

    // Compare the entered password with the hashed password
    bcrypt.compare(password, hashedPassword, (err, isMatch) => {
      if (err) return res.status(500).json({ message: 'Error validating password' });

      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid Credentials' });
      }

      // Successful login
      res.status(200).json({ message: 'Login successful', userId: id });
    });
  });
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  const query = 'SELECT id, name, email, company, age, dob FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching user:', err);
      return res.status(500).json({ message: 'Database error while fetching user' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ user: results[0] });
  });
});

app.delete('/user-delete', (req, res) => {
  const { id } = req.body;

  if (!id) return res.status(400).json({ message: 'User ID is required' });

  const deleteQuery = 'DELETE FROM users WHERE id = ?';

  db.query(deleteQuery, [id], (err, result) => {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Account deleted successfully' });
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
