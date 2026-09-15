const nodemailer = require('nodemailer');

// Create transporter instance using SMTP credentials
const transporter = nodemailer.createTransport({
  service: 'gmail', // Or custom SMTP (e.g., host: 'smtp.mailtrap.io', port: 2525)
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_EMAIL_PASS,
  },
});

// Helper function to dispatch notification emails
async function sendNewUserNotification(newUser) {
  const mailOptions = {
    from: `"Scheduler App" <${process.env.ADMIN_EMAIL}>`,
    to: process.env.ADMIN_EMAIL,
    subject: `🔔 New User Registered: ${newUser.username}`,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px;">
        <h2 style="color: #1d4ed8; margin-top: 0;">New Account Notification</h2>
        <p>A new account was just created on your Meeting Schedule Manager:</p>
        <ul style="line-height: 1.8;">
          <li><strong>Username:</strong> ${newUser.username}</li>
          <li><strong>Email:</strong> ${newUser.email || 'No email provided'}</li>
          <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
        </ul>
      </div>
    `,
  };

  return transporter.sendMail(mailOptions);
}

module.exports = { sendNewUserNotification };