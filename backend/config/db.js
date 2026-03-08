const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/threatmap';
        await mongoose.connect(uri);
        console.log(`[MongoDB] Connected properly to ${uri}`);
    } catch (error) {
        console.error('[MongoDB] Connection error:', error.message);
        process.exit(1);
    }
};

module.exports = connectDB;
