require('dotenv').config();
const app = require('./src/app');
const mongoose = require('mongoose');
const logger = require('./src/utils/logger');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/wenmoon';

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    logger.info('Connected to MongoDB');
    app.listen(PORT, () => {
        logger.info(`Server running on port ${PORT}`);
    });
})
.catch((error) => {
    logger.error('MongoDB connection error:', error);
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    logger.error('Unhandled Promise Rejection:', err);
    // Close server & exit process
    process.exit(1);
});
