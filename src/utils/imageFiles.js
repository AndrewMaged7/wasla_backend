const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const HttpError = require('./HttpError');
const { AVATAR_DIR, PRIVATE_DIR } = require('../config/constants');

// creates the upload folders if they do not exist yet
function ensureUploadDirs() {
  fs.mkdirSync(AVATAR_DIR, { recursive: true });
  fs.mkdirSync(PRIVATE_DIR, { recursive: true });
}

// detects the image type from the first bytes of the file (not from its name or the client-sent mimetype)
function detectImage(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  return null;
}

// validates the image and saves it with a random file name, returns the file name
async function saveImage(dir, file) {
  const ext = detectImage(file.buffer);
  if (!ext) throw new HttpError(400, 'File must be an image (JPG, PNG or WEBP)');
  const filename = `${crypto.randomBytes(16).toString('hex')}.${ext}`;
  await fs.promises.writeFile(path.join(dir, filename), file.buffer);
  return filename;
}

function removeFile(dir, filename) {
  if (!filename) return;
  fs.promises.unlink(path.join(dir, path.basename(filename))).catch(() => {});
}

function removeIdentityDocs(identity) {
  if (!identity || !identity.docs) return;
  ['front', 'back', 'selfie'].forEach((k) => removeFile(PRIVATE_DIR, identity.docs[k]));
}

module.exports = { ensureUploadDirs, detectImage, saveImage, removeFile, removeIdentityDocs };