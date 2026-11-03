// the env file must be loaded first (it reads .env and checks JWT_SECRET)
const env = require('./config/env');
const app = require('./app');
const { connectDatabase } = require('./config/database');
const { ensureUploadDirs } = require('./utils/imageFiles');

async function start() {
  ensureUploadDirs();
  await connectDatabase();
  app.listen(env.PORT, () => console.log(`Server running on http://localhost:${env.PORT}`));
}

start().catch((err) => {
  console.error('ERROR: failed to start the server:', err.message);
  process.exit(1);
});