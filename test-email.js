// test-email.js
require('dotenv').config();
const { sendNewUserNotification } = require('./utils/mailer');

console.log('Testing with Email:', process.env.ADMIN_EMAIL);

sendNewUserNotification({ username: 'TestUser', email: 'test@example.com' })
  .then(() => console.log('✅ Email sent successfully! Check your inbox/spam folder.'))
  .catch((err) => console.error('❌ Email failed with error:', err));