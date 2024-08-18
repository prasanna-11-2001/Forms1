const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sql = require('mysql2');
const cors = require('cors'); // Import cors

const app = express();
app.use(cors()); // Use cors middleware
app.use(bodyParser.json());

const conn = sql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'prasanna'
});

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret_key';

// Signup route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    conn.query(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedPassword],
        (err, results) => {
            if (err) {
                console.error('Database error:', err.message);
                return res.status(500).json({ error: 'Database error: ' + err.message });
            }
            res.status(201).json({ message: 'User created Successfully' });
        }
    );
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    conn.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).json({ error: 'Database error: ' + err.message });
        }
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = results[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    });
});

// Start server
app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
