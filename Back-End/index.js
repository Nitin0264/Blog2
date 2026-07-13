import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import bcrypt from "bcryptjs";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import jwt from "jsonwebtoken";
import cors from "cors";

// Initialize Express app
const app = express();
const JWT_SECRET = "my_super_secret_key";

// ====================== PATH CONFIGURATION ======================
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// View Engine Configuration
const viewsPath = join(__dirname, 'views');
app.set('views', viewsPath);
app.set('view engine', 'ejs');

console.log("Express views directory is set to:", viewsPath);

// ====================== GLOBAL MIDDLEWARE ======================
app.use(cors());                        // Enable Cross-Origin requests safely
app.use(express.json());                // Read modern Axios JSON bodies (Crucial!)
app.use(express.urlencoded({ extended: true })); // Read classic HTML form data

// Session configuration - keeping for old routes fallback
app.use(session({
  secret: "my_super_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 }
}));

// ====================== DATABASE CONNECTION ======================
// ... Leave your database and routes exactly as they are below this line!

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


// Security Middleware: Decodes the JWT token from incoming Axios request headers
const verifyToken = (req, res, next) => {
  // 1. Look for the token inside the incoming 'Authorization' request header
  const authHeader = req.headers['authorization'];
  
  // Axios sends it as: "Bearer <token_string>". Let's split it and get just the token string.
  const token = authHeader && authHeader.split(' ')[1];

  // If no token is provided at all, shut down the request immediately
  if (!token) {
    return res.status(401).json({ success: false, message: "Access Denied. No token provided!" });
  }

  try {
    // 2. Use your secret key to verify if the token is authentic and un-tampered with
    const verifiedPayload = jwt.verify(token, JWT_SECRET);
    
    // 3. Attach the decrypted payload details directly onto the request object
    req.user = verifiedPayload; 
    
    // 4. Everything looks perfect! Let the request move forward to the actual route handler
    next();
  } catch (err) {
    // If the token is expired, fake, or modified, trigger an error response
    return res.status(403).json({ success: false, message: "Invalid or expired authorization token!" });
  }
};
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

// using this onepost for the axios and the jwt

app.post("/api/login", async (req,res)=>
{
  const{username,password} = req.body;
  
  try{
    const user = await User.findOne({username:username});
    if(!user){
      return res.status(400).json({
        success:false,message:"Invalid username or password"
      })
    }
    const isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch)
    {
      return res.status(400).json({success:false,message:"invalid username or password"})
    }
   const tokenPayload = {
    userId :user._id,
    username:user.username,
    role:user.role
   };
   const token = jwt.sign(tokenPayload,JWT_SECRET,{
    expiresIn:"1h"
   });
   return res.status(200).json({
    success:true,
    message:"Login Successful",
    token:token,
    user:{username:user.username,role:user.role}
   });

  }
  catch(err){
    console.error("API Login Error",err);
    return res.status(500).json({
      success:false,message:"an error occurred while loging in "
    })
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

// inseting the new routes for the admin fixed login

// ====================== ADVANCED MANAGEMENT API ROUTES ======================

// 1. GET: Fetch all registered users from the database (Secure: Admin Only)
app.get("/api/users", verifyToken, async (req, res) => {
  // Security Guard: Check if the decoded JWT profile role is 'admin'
  if (req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied. Admins only." });
  }

  try {
    // Fetch all users, but explicitly exclude the password field ("-password") for data safety
    const users = await User.find({}, "-password"); 
    return res.status(200).json({ success: true, users: users });
  } catch (err) {
    console.error("Error fetching user directory:", err);
    return res.status(500).json({ success: false, message: "Failed to retrieve user directory." });
  }
});

// 2. DELETE: Remove a user account permanently from MongoDB (Secure: Admin Only)
app.delete("/api/users/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied. Admins only." });
  }

  try {
    const userIdToDelete = req.params.id;

    // Safety Lock: Prevent an admin from accidentally deleting their own active account!
    if (userIdToDelete === req.user.userId) {
      return res.status(400).json({ success: false, message: "Operation blocked! You cannot delete your own admin profile." });
    }

    await User.findByIdAndDelete(userIdToDelete);
    return res.status(200).json({ success: true, message: "User account permanently purged." });
  } catch (err) {
    console.error("Error deleting user account:", err);
    return res.status(500).json({ success: false, message: "Database deletion failure." });
  }
});

// 3. DELETE: Remove a blog post article from MongoDB (Secure: Admin Only)
app.delete("/api/blogs/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied. Admins only." });
  }

  try {
    const blogId = req.params.id;
    await Blog.findByIdAndDelete(blogId);
    return res.status(200).json({ success: true, message: "Technical article removed successfully." });
  } catch (err) {
    console.error("Error deleting blog article:", err);
    return res.status(500).json({ success: false, message: "Database failed to delete article entry." });
  }
});

// 5. PUT: Securely update an existing blog post article inside MongoDB (Secure: Admin Only)
app.put("/api/blogs/:id", verifyToken, async (req, res) => {
  // Security check: Only let authenticated admins pass
  if (req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied. Admins only." });
  }

  const { title, description, imageUrl } = req.body;
  const blogId = req.params.id;

  // Simple input verification validation check
  if (!title || !description || !imageUrl) {
    return res.status(400).json({ success: false, message: "All form modification fields are required!" });
  }

  try {
    // Find the item by its database ID and replace its fields with the new incoming data
    const updatedBlog = await Blog.findByIdAndUpdate(
      blogId,
      { title: title, description: description, imageUrl: imageUrl },
      { new: true } // { new: true } instructs mongoose to return the newly updated version of the document
    );

    if (!updatedBlog) {
      return res.status(404).json({ success: false, message: "Target blog post could not be found." });
    }

    return res.status(200).json({ 
      success: true, 
      message: "Article entry rewritten successfully!", 
      blog: updatedBlog 
    });
  } catch (err) {
    console.error("Error editing database blog post entry:", err);
    return res.status(500).json({ success: false, message: "Database update transaction failed." });
  }
});
// 4. GET: Server-Side route to render our upcoming Admin Panel HTML interface page
app.get("/admin-panel", (req, res) => {
  res.render("admin-panel");
});


// GET: Show Create Blog Page (Admin Only)
app.get("/create-blog", (req, res) => {
  res.render("create-blog", { error: null });
});

app.get("/api/blogs", async (req, res) => {
  try {
    // Changed "blog" to "blogs" to match your return statement below
    const blogs = await Blog.find().sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      blogs: blogs
    });
  } catch (err) {
    console.error("API fetch blogs error :", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching articles from the Database"
    });
  }
});

// API Route: Securely Create New Blog Post (Admin Only)
// Notice how we inject 'verifyToken' right into the middle of the route parameters!
app.post("/api/blogs", verifyToken, async (req, res) => {
  // 1. Authorization Check: verifyToken already decoded the user profile into req.user
  if (req.user.role !== "admin") {
    return res.status(403).json({ 
      success: false, 
      message: "Access Denied. Only administration profiles can publish articles!" 
    });
  }

  const { title, description, imageUrl } = req.body;

  // 2. Form Input Validation Check
  if (!title || !description || !imageUrl) {
    return res.status(400).json({ 
      success: false, 
      message: "All validation fields are strictly required!" 
    });
  }

  try {
    // 3. Persist the record to MongoDB
    const newBlog = await Blog.create({
      title: title,
      description: description,
      imageUrl: imageUrl
    });

    return res.status(201).json({
      success: true,
      message: "Blog post published successfully via JWT authorization!",
      blog: newBlog
    });

  } catch (err) {
    console.error("API Blog Creation Error:", err);
    return res.status(500).json({ 
      success: false, 
      message: "Database insertion error. Failed to save post." 
    });
  }
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
  console.log('🚀thisistheg 8000');
});