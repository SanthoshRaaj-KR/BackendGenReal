require('dotenv').config();
const nodemailer = require('nodemailer');

(async () => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  try {
    const info = await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: 'your_email_here@gmail.com',
      subject: 'Test Email',
      text: 'Hello from nodemailer test',
    });
    console.log('Email sent:', info.response);
  } catch (err) {
    console.error('Nodemailer error:', err);
  }
})();
