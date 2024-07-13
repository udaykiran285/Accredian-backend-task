const mysql = require('mysql2/promise');
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config()

const app = express();
app.use(cors());
app.use(express.json());

let connection;

// Async function to establish a connection
async function initializeDatabase() {
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
      ssl: {
        rejectUnauthorized: false
      }
    });

    console.log('Connected to the MySQL database.');
  } catch (err) {
    console.error('Error connecting to the database:', err);
  }
}


// Initialize the database
initializeDatabase();

function generateReferralCode() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let referralCode = '';
  for (let i = 0; i < 4; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    referralCode += characters[randomIndex];
  }
  return referralCode;
}

// Middleware to check email in both user and user_referrals tables
async function checkEmailExists(req, res, next) {
  const { email } = req.body;

  try {
    // Check if the email exists in the user table
    const [existingUserByEmail] = await connection.execute(
      'SELECT * FROM user WHERE email = ?',
      [email]
    );

    if (existingUserByEmail.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Check if the email exists in the user_referrals table
    const [existingReferralByEmail] = await connection.execute(
      'SELECT * FROM user_referrals WHERE referee_email = ?',
      [email]
    );

    if (existingReferralByEmail.length > 0) {
      return res.status(400).json({ message: 'Already referred by another person' });
    }

    next();
  } catch (err) {
    console.error('Error during email check:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
}

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const authHeader = req.headers.authorization.split(" ");
  
  if (authHeader.length !== 2 || authHeader[0] !== 'Bearer') {
    return res.status(401).json({ error: 'Invalid authorization header format' });
  }

  const token = authHeader[1];

  try {
    const payload = jwt.verify(token, "my_secret_key");
    req.user = payload;
    next();
  } catch (e) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// Signup route
app.post("/signup", async (req, res) => {
  const { username, email, password, referralCode } = req.body;
  const hashed_password = await bcrypt.hash(password, 10);

  try {
    // Check if the username already exists
    const [existingUserByUsername] = await connection.execute(
      'SELECT * FROM user WHERE username = ?',
      [username]
    );

    if (existingUserByUsername.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Check if the email already exists
    const [existingUserByEmail] = await connection.execute(
      'SELECT * FROM user WHERE email = ?',
      [email]
    );

    if (existingUserByEmail.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    let referredBy = null;

    // Check if a valid referral code is provided
    if (referralCode !== "") {
      const [validReferralCode] = await connection.execute(
        'SELECT * FROM user WHERE referral_code = ?',
        [referralCode]
      );

      if (validReferralCode.length === 0) {
        return res.status(400).json({ message: 'Invalid referral code' });
      }

      referredBy = validReferralCode[0].username;

      // Update the referee_status to 'Successful' in the user_referrals table
      await connection.execute(
        'UPDATE user_referrals SET referee_status = ? WHERE referee_email = ? AND referee_status = ?',
        ['Successful', email, 'Pending']
      );
    }

    let generatedReferralCode;
    let isUnique;

    // Generate a unique referral code
    do {
      generatedReferralCode = generateReferralCode();
      const [existingUserByReferralCode] = await connection.execute(
        'SELECT * FROM user WHERE referral_code = ?',
        [generatedReferralCode]
      );
      isUnique = existingUserByReferralCode.length === 0;
    } while (!isUnique);

    // Insert the new user
    await connection.execute(
      'INSERT INTO user (username, email, password, referral_code, referred_by) VALUES (?, ?, ?, ?, ?)',
      [username, email, hashed_password, generatedReferralCode, referredBy]
    );

    const payload = { username };
    const jwtToken = jwt.sign(payload, "my_secret_key");
    res.status(200).json({ jwtToken });
  } catch (err) {
    console.error('Error during signup:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [existingUser] = await connection.execute(
      'SELECT * FROM user WHERE email = ?',
      [email]
    );

    if (existingUser.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, existingUser[0].password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const payload = { username: existingUser[0].username };
    const jwtToken = jwt.sign(payload, "my_secret_key");
    res.status(200).json({ jwtToken });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Add referre route
app.post("/add-referre", verifyToken, checkEmailExists, async (req, res) => {
  const { name, email } = req.body;

  try {
    const [userDetails] = await connection.execute(
      'SELECT id FROM user WHERE username = ?',
      [req.user.username]
    );

    if (userDetails.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await connection.execute(
      'INSERT INTO user_referrals (referred_user_id, referee_name, referee_email, referee_status) VALUES (?, ?, ?, ?)',
      [userDetails[0].id, name, email, 'Pending']
    );

    res.status(200).json({ message: 'Referee added successfully' });
  } catch (e) {
    console.error('Error during adding referee:', e);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Referrals data route
app.get("/referrals-data", verifyToken, async (req, res) => {
  try {
    const [userDetails] = await connection.execute(
      'SELECT id FROM user WHERE username = ?',
      [req.user.username]
    );

    if (userDetails.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const [referrals] = await connection.execute(
      'SELECT * FROM user_referrals WHERE referred_user_id = ?',
      [userDetails[0].id]
    );

    res.status(200).json({ referrals });
  } catch (e) {
    console.error('Error during fetching referrals:', e);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get("/user-details", verifyToken, async (req, res) => {
  try {
    const [userData] = await connection.execute(
      'SELECT id, username, email, referral_code, referred_by FROM user WHERE username = ?',
      [req.user.username]
    );

    if (userData.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDetails = userData[0];
    res.status(200).json({ userDetails });
  } catch (e) {
    console.error('Error fetching user details:', e);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start the server
app.listen(process.env.DB_PORT || 4000, () => {
  console.log('Server is running on port ',process.env.DB_PORT);
});
