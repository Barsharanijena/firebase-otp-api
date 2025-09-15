const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.PORT ;

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/firebase-otp')
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.error('MongoDB connection error:', error));

app.use('/api/auth', authRoutes);

app.get('/health', (req, res) => {
    res.json({ status: 'OK' });
});
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;