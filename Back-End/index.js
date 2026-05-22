import express from "express"
import mongoose from "mongoose"
import session from "express-session"
import bcrypt from "bcryptjs"
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Initialize express app
const app = express();

// Reconstruct __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// View Engine Configuration
const viewsPath = join(__dirname, 'views');
app.set('views', viewsPath);
app.set('view engine', 'ejs');

console.log("Express views directory is set to:", viewsPath);

// Middleware
app.use(express.urlencoded({
  extended: true
}))

app.use(session({
  secret: "my_super_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 }
}))

// MongoDB Connection
mongoose.connect("mongodb://127.0.0.1:27017/adminBlogDB")
.then(() => {
  console.log("mongoDb connected Successfully!");
})
.catch((err) => {
  console.log("database connection error", err)
})

// Database Schemas & Models
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
    default: "user"
  }
})
const User = mongoose.model("User", userSchema)

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
const Blog = mongoose.model("Blog", blogSchema)

// --- ROUTES ---

// GET Route: Display Register Page
app.get("/register", (req, res) => {
  res.render("register", { error: null });
})

// POST Route: Process Registration
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ username: username });
    
    if (existingUser) {
      return res.render("register", { error: "Username already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username: username,
      password: hashedPassword,
      role: role
    });

    res.redirect("/login");

  } catch (err) {
    res.render("register", { error: "An error occurred during registration." });
  }
});

// GET Route: Display Login Page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
})

// POST Route: Process Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username: username });

    if (!user) {
      return res.render("login", { error: "Invalid username or password!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.render("login", { error: "Invalid username or password!" });
    }

    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.role = user.role;

    res.redirect("/");

  } catch (err) {
    res.render("login", { error: "An error occurred during login." });
  }
});

app.get("/logout",(req,res)=>
{
  req.session.destroy((err)=>
  {
    if(err)
    {
      console.error("errror destroying the session",err);
      return res.status(500).send("could not log out. Try Again");
    }
    res.clearCookie("connect.sid");
    res.redirect("/login");
  })
})


app.get("/create-blog",(req,res)=>
{
  if(!req.session.userId || req.session.role !== "admin")
  {
    return res.status(403).send("Access denied. admins only ")
  }
  res.render("create-blog",{error:null})
})

app.post("/create-blog", async (req,res)=>
{
  if(!req.session.userId  || req.session.role !== "admin")
  {
    return res.status(403).send("Access denied")
  }
  const{title,description,imageUrl} = req.body;

  if(!title ||!description ||!imageUrl)
  {
    return res.render("create-blog",{error:"All fields are required"})
  }
  try{
    await Blog.create({
      title:title,
      description:description,
      imageUrl:imageUrl
    })
    res.redirect("/");
  }
  catch(err)
  {
    console.log("error saving blog post:",err)
    res.render("create-blog",{error: "Database error. failed to save psot "})
  }
});



// GET Route: Dashboard Home Page
app.get("/", async (req, res) => {
  try {
    // 1. Fetch all posts ordered from newest to oldest
    const blogs = await Blog.find().sort({ createdAt: -1 });
    
    // 2. Render home template passing both the posts array and the session user profile
    res.render("home", { 
      blogs: blogs, 
      user: req.session.userId ? { username: req.session.username, role: req.session.role } : null 
    });
  } catch (err) {
    console.error("Error fetching blogs:", err);
    res.status(500).send("Internal Server Error");
  }
});
// Start Server
app.listen(8000, () => {
  console.log('server is running on port 8000')
})