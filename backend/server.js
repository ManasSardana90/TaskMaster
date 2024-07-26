const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;

app.use(cors({
  origin: [FRONTEND_URL],
  credentials: true,
}));

app.use(express.json());
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('Could not connect to MongoDB Atlas', err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  googleId: String,
  githubId: String,
});

const todoSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  text: { type: String, required: true },
  completed: Boolean,
});

const User = mongoose.model('User', userSchema);
const Todo = mongoose.model('Todo', todoSchema);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `https://taskmaster-b766.onrender.com/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = new User({
        username: profile.displayName,
        googleId: profile.id,
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'https://taskmaster-b766.onrender.com/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    if (!user) {
      user = new User({
        username: profile.username,
        githubId: profile.id,
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`${FRONTEND_URL}/?token=${token}`);
  });

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`${FRONTEND_URL}/?token=${token}`);
  });

app.post('/register', [
  body('username').isLength({ min: 1 }).trim().escape().withMessage('Username is required'),
  body('password').isLength({ min: 6 }).trim().escape().withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
  } catch (err) {
    res.status(400).send('Error registering user');
  }
});

app.post('/login', [
  body('username').isLength({ min: 1 }).trim().escape().withMessage('Username is required'),
  body('password').isLength({ min: 1 }).trim().escape().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ errors: [{ msg: 'Invalid username or password' }] });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ errors: [{ msg: 'Invalid username or password' }] });
  }
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).send('Unauthorized');
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Forbidden');
    }
    req.user = user;
    next();
  });
};

app.get('/todos', authenticateJWT, async (req, res) => {
  try {
    const todos = await Todo.find({ userId: req.user.userId });
    res.json(todos);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/todos', authenticateJWT, async (req, res) => {
  if (!req.body.text) {
    return res.status(400).send('Text is required');
  }
  try {
    const newTodo = new Todo({
      userId: req.user.userId,
      text: req.body.text,
      completed: false,
    });
    await newTodo.save();
    res.json(newTodo);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/todos/:id', authenticateJWT, async (req, res) => {
  try {
    const todo = await Todo.findById(req.params.id);
    if (todo.userId.toString() !== req.user.userId) {
      return res.status(403).send('Forbidden');
    }
    todo.completed = !todo.completed;
    await todo.save();
    res.json(todo);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/todos/:id', authenticateJWT, async (req, res) => {
  try {
    const result = await Todo.findByIdAndDelete(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Serve static files from the React app
app.use(express.static(path.join(__dirname, '../todo-app/build')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../todo-app/build/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
