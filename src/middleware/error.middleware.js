const multer = require('multer');
const HttpError = require('../utils/HttpError');

// 404 for any route that does not exist
function notFound(req, res) {
  res.status(404).json({ success: false, message: 'Route not found' });
}

// one place that turns every error into a JSON response
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ success: false, message: err.message, ...(err.extra || {}) });
  }
  if (err instanceof multer.MulterError) {
    const message = err.code === 'LIMIT_FILE_SIZE' ? 'File is too large' : 'Invalid uploaded files';
    return res.status(400).json({ success: false, message });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, message: 'Invalid JSON' });
  }
  console.error('ERROR:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
}

module.exports = { notFound, errorHandler };