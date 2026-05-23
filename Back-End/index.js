import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import bcrypt from "bcryptjs";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Initialize Express app
const app = express();

// ====================== PATH CONFIGURATION ======================
// Reconstruct __dirname for ES Modules (since __dirname is not available by default in ES modules)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// View Engine Configuration
const viewsPath = join(__dirname, 'views');
app.set('views', viewsPath);
app.set('view engine', 'ejs');

console.log("Express views directory is set to:", viewsPath);

// ====================== MIDDLEWARE ======================

// Parse URL-encoded form data (from HTML forms)
app.use(express.urlencoded({ extended: true }));

// Session configuration - used for maintaining user login state
app.use(session({
  secret: "my_super_secret_key",        // Secret key to sign the session ID cookie
  resave: false,                        // Don't save session if unmodified
  saveUninitialized: false,             // Don't create session until something is stored
  cookie: { maxAge: 3600000 }           // Cookie expires in 1 hour (3600000 ms)
}));

// ====================== DATABASE CONNECTION ======================

// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/adminBlogDB")
  .then(() => {
    console.log("✅ MongoDB connected Successfully!");
  })
  .catch((err) => {
    console.log("❌ Database connection error:", err);
  });

// ====================== SCHEMAS & MODELS ======================

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: "user"          // Default role is 'user', can be 'admin'
  }
});
const User = mongoose.model("User", userSchema);

// Blog Schema
const blogSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  imageUrl: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
const Blog = mongoose.model("Blog", blogSchema);

// ====================== ROUTES ======================

// GET: Show Registration Page
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});


app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  // const username = req.body.username;
  // const password = req.body.password;
  // const role = req.body.role;

  try {
    // Check if username already exists
    const existingUser = await User.findOne({ username: username });

    if (existingUser) {
      return res.render("register", { error: "Username already exists!" });
    }

    // Hash password before saving (Security Best Practice)
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username: username,
      password: hashedPassword,
      role: role || "user"   // Default to user if role not provided
    });

    res.redirect("/login");

  } catch (err) {
    res.render("register", { error: "An error occurred during registration." });
  }
});

// GET: Show Login Page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// POST: Handle Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username: username });

    if (!user) {
      return res.render("login", { error: "Invalid username or password!" });
    }

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      
      return res.render("login", { error: "Invalid username or password!" });
    }

    // Store user info in session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.role = user.role;

    res.redirect("/");

  } catch (err) {
    res.render("login", { error: "An error occurred during login." });
  }
});

// Logout Route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Could not log out. Try again.");
    }
    res.clearCookie("connect.sid");   // Clear session cookie
    res.redirect("/login");
  });
});

// ====================== ADMIN ROUTES ======================

// GET: Show Create Blog Page (Admin Only)
app.get("/create-blog", (req, res) => {
  if (!req.session.userId || req.session.role !== "admin") {
    return res.status(403).send("Access denied. Admins only.");
  }
  res.render("create-blog", { error: null });
});

// POST: Create New Blog (Admin Only)
app.post("/create-blog", async (req, res) => {
  if (!req.session.userId || req.session.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  const { title, description, imageUrl } = req.body;

  if (!title || !description || !imageUrl) {
    return res.render("create-blog", { error: "All fields are required" });
  }

  try {
    await Blog.create({
      title: title,
      description: description,
      imageUrl: imageUrl
    });
    res.redirect("/");
  } catch (err) {
    console.log("Error saving blog post:", err);
    res.render("create-blog", { error: "Database error. Failed to save post." });
  }
});

// ====================== HOME / DASHBOARD ======================

// GET: Home Page - Show All Blogs
app.get("/", async (req, res) => {
  try {
    // Fetch all blogs sorted by newest first
    const blogs = await Blog.find().sort({ createdAt: -1 });

    // Pass blogs and current user info to the view
    res.render("home", {
      blogs: blogs,
      user: req.session.userId
        ? { username: req.session.username, role: req.session.role }
        : null
    });
  } catch (err) {
    console.error("Error fetching blogs:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Start Server
app.listen(8000, () => {
  console.log('🚀 Server is running on port 8000');
});