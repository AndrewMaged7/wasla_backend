const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const env = require('./config/env');
const { UPLOAD_DIR } = require('./config/constants');
const routes = require('./routes');
const { notFound, errorHandler } = require('./middleware/error.middleware');

const app = express();

if (env.TRUST_PROXY) app.set('trust proxy', 1);

// crossOriginResourcePolicy: lets profile photos load from the mobile app / frontend
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// profile photos only (identity documents live in a different folder that is not public)
app.use('/uploads', express.static(UPLOAD_DIR, { index: false, dotfiles: 'deny' }));

app.get('/', (req, res) => res.json({ success: true, message: 'API is running' }));

app.use('/api', routes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;