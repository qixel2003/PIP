import express from 'express';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import db from './db.js';

const app = express();
app.use(express.json());

// Use the PORT from environment variables, fallback to 3000
const PORT = process.env.PORT || 3000;
const scryptAsync = promisify(crypto.scrypt);

/**
 * Hashes a password asynchronously using the built-in crypto module.
 * @param {string} password
 * @returns {Promise<string>} Salt and Hash combined
 */
const hashPassword = async (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = await scryptAsync(password, salt, 64);
    return `${salt}:${derivedKey.toString('hex')}`;
};

/**
 * Simple email validation regex.
 */
const isValidEmail = (email) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

// POST /api/register
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    // 1. Acceptance Criteria: Check if all fields are received
    if (!name || !email || !password) {
        return res.status(400).json({
            error: 'Missing credentials',
            message: 'Name, email, and password are required.'
        });
    }

    // 2. Validation: Ensure email format is correct
    if (!isValidEmail(email)) {
        return res.status(400).json({
            error: 'Invalid email',
            message: 'Please provide a valid email address.'
        });
    }

    try {
        // 3. Acceptance Criteria: Hash the password securely (Async)
        const hashedPassword = await hashPassword(password);

        // 4. Acceptance Criteria: Insert user into 'users' table
        const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
        const params = [name, email, hashedPassword];

        db.run(sql, params, function (err) {
            if (err) {
                // 5. Acceptance Criteria: Handle unique email constraint
                if (err.errno === 19 || err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({
                        error: 'Conflict',
                        message: 'An account with this email already exists.'
                    });
                }
                console.error('Database Error:', err.message);
                return res.status(500).json({ error: 'Internal server error' });
            }

            // 6. Acceptance Criteria: Return success message and user data
            res.status(201).json({
                message: 'User registered successfully',
                user: {
                    id: this.lastID,
                    name: name,
                    email: email
                }
            });
        });
    } catch (error) {
        console.error('Hashing Error:', error);
        res.status(500).json({ error: 'Internal server error during registration.' });
    }
});

app.listen(PORT, () => {
    console.log(`PIP Backend running on http://localhost:${PORT}`);
});