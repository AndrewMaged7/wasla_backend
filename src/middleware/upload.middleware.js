const multer = require('multer');
const { AVATAR_MAX_BYTES, ID_DOC_MAX_BYTES } = require('../config/constants');

// files are kept in memory, checked (real image?) and only then written to disk by utils/imageFiles.js
const uploadAvatar = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: AVATAR_MAX_BYTES, files: 1 },
});

const uploadIdDocs = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: ID_DOC_MAX_BYTES, files: 3 },
});

module.exports = { uploadAvatar, uploadIdDocs };