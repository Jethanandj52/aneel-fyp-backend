const express = require('express');
const msgRoutes = express.Router();
const { UserMsg } = require('../modles/userMsg');
const nodemailer = require('nodemailer');

const emailService = process.env.SERVICE;
const myEmail = process.env.MY_EMAIL;
const passKey = process.env.PASS_KEY;

msgRoutes.post('/addMessage', async (req, res) => {
  try {
    const { fullName, email, message } = req.body;

    // 1. Save message to DB
    const msg = new UserMsg({ fullName, email, message });
    await msg.save();

    // 2. Send Email to Admin
    const transporter = nodemailer.createTransport({
      service: emailService,
      auth: {
        user: myEmail,
        pass: passKey,
      },
    });

    const mailOptions = {
      from: `APIverse <${myEmail}>`,  // ✅ You (as sender)
      to: myEmail,                    // ✅ Admin (receiver)
      replyTo: email,                 // ✅ When admin replies, it'll go to user
      subject: `New Feedback from ${fullName}`,
      html: `
        <h2>User Name: ${fullName}</h2>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong> ${message}</p>
        
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({ message: 'Feedback sent and saved successfully!' });

  } catch (error) {
    console.error('Error sending feedback:', error);
    res.status(400).json({ error: error.message });
  }
});

module.exports = msgRoutes;
