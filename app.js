// app.js
require('dotenv').config();

const express       = require('express');
const mongoose      = require('mongoose');
const session       = require('express-session');
const MongoStore    = require('connect-mongo');
const bcrypt        = require('bcryptjs');
const path          = require('path');
const helmet        = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── 1. DATABASE SETUP ──────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB error:', err));

// ─── 2. USER MODEL ─────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// ─── 3. MIDDLEWARE ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  name: '_sid',                        // generic cookie name
  secret: process.env.SESSION_SECRET,  
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({           // store sessions in MongoDB
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60,            // 1 hour
  }
}));

// Simple auth-check middleware
function ensureLoggedIn(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ─── 4. ROUTES ─────────────────────────────────────────────────────────────────

// Serve static HTML
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', ensureLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// POST /register
app.post(
  '/register',
  // Validate inputs
  body('username').trim().isLength({ min: 3 }).escape(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Validation error. Username must be ≥3 chars; password ≥6 chars.');
    }
    const { username, password } = req.body;
    try {
      if (await User.findOne({ username })) {
        return res.status(400).send('Username already taken. <a href="/register">Try again</a>');
      }
      const passwordHash = await bcrypt.hash(password, 12);
      await User.create({ username, passwordHash });
      res.redirect('/login');
    } catch (err) {
      console.error(err);
      res.status(500).send('Registration failure. Please try again.');
    }
  }
);

// POST /login
app.post(
  '/login',
  body('username').trim().escape(),
  body('password').exists(),
  async (req, res) => {
    const { username, password } = req.body;
    try {
      const user = await User.findOne({ username });
      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
      }
      // Regenerate session to prevent fixation
      req.session.regenerate(err => {
        if (err) return res.status(500).send('Session error');
        req.session.userId = user._id;
        res.redirect('/dashboard');
      });
    } catch (err) {
      console.error(err);
      res.status(500).send('Login failure. Please try again.');
    }
  }
);

// POST /logout
app.post('/logout', ensureLoggedIn, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Logout error');
    res.clearCookie('_sid');
    res.redirect('/login');
  });
});

// ─── 5. START SERVER ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
