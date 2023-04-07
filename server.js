// Import necessary packages
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Set up express app
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set up MongoDB connection
mongoose.connect('mongodb://localhost:27017', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('MongoDB connected'));

// Define user schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
  name: { type: String }
});

// Hash password before saving user to database
userSchema.pre('save', function (next) {
  const user = this;
  bcrypt.hash(user.password, 10, (err, hash) => {
    if (err) return next(err);
    user.password = hash;
    next();
  });
});

// Define user model
const User = mongoose.model('User', userSchema);

// Handle user sign up requests
app.post('/signup', async (req, res) => {
  try {
    // Check if email already exists in database
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    // Create new user
    const newUser = new User({
      email: req.body.email,
      password: req.body.password,
      name: req.body.name
    });
    await newUser.save();

    // Return success message
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Handle user login requests
app.post('/login', async (req, res) => {
  try {
    // Find user with matching email
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    // Compare password hash
    bcrypt.compare(req.body.password, user.password, (err, result) => {
      if (err || !result) return res.status(401).json({ message: 'Invalid email or password' });

      // Generate authentication token and return to user
      const token = 'my_auth_token';
      res.status(200).json({ token: token });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protect routes with authentication middleware
const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token || token !== 'my_auth_token') return res.status(401).json({ message: 'Unauthorized' });
  next();
};

// Example protected route
app.get('/protected', authenticateUser, (req, res) => {
  res.status(200).json({ message: 'You have access to protected route' });
});

// Start server
app.listen(3000, () => console.log('Server started'));
