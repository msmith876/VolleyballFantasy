require('dotenv').config();
// LOGIN //

// Import dependencies
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

// Initialize app and middleware
const app = express();
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB (adjust connection string as needed)
mongoose.connect('mongodb://localhost:27017/volleyballFantasyApp', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Define User schema and model
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

const User = mongoose.model('User', userSchema);

// Authentication and authorization middleware
const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Access denied' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token' });
    }
};

const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
    next();
};

// Route: Sign Up
app.post('/signup', async (req, res) => {
    const { email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword, role });
        await newUser.save();

        // Save user data to a JSON file
        const filePath = path.join(__dirname, 'users.json');
        let users = [];

        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath);
            users = JSON.parse(data);
        }

        users.push({ email, password: hashedPassword, role });
        fs.writeFileSync(filePath, JSON.stringify(users, null, 2));

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user', error });
    }
});

// Route: Log In
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid email or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, { httpOnly: true });
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

// Route: Log Out
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logout successful' });
});

// Protected Route: Access Draft List (Admin Only)
app.get('/draft-list', authenticate, authorizeAdmin, async (req, res) => {
    // Code to retrieve draft list for admin use
    res.status(200).json({ message: 'Draft list data' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
