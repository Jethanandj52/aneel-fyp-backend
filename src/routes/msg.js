const express = require('express');
const msgRoutes = express.Router();
const { UserMsg } = require('../modles/userMsg');
const nodemailer = require('nodemailer');

const emailService = process.env.SERVICE;
const myEmail = process.env.MY_EMAIL;
const passKey = process.env.PASS_KEY;

// ✅ Add Message Route
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
      from: `APIverse <${myEmail}>`,  // sender
      to: myEmail,                    // admin
      replyTo: email,                 // reply goes to user
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

// ✅ Get All Messages
msgRoutes.get('/all', async (req, res) => {
  try {
    const msgs = await UserMsg.find().sort({ createdAt: -1 });
    res.status(200).json({ messages: msgs });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// ✅ Reply to User
msgRoutes.post('/reply', async (req, res) => {
  try {
    const { email, replyMessage } = req.body;

    if (!email || !replyMessage) {
      return res.status(400).json({ error: "Email and reply message are required" });
    }

    const transporter = nodemailer.createTransport({
      service: emailService,
      auth: {
        user: myEmail,
        pass: passKey,
      },
    });

    const mailOptions = {
      from: `APIverse <${myEmail}>`,
      to: email, // ✅ reply goes to user
      subject: "Reply from Admin - APIverse",
      html: `
        <p><strong>Admin Reply:</strong></p>
        <p>${replyMessage}</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Reply sent successfully!" });
  } catch (error) {
    console.error("Error sending reply:", error);
    res.status(500).json({ error: "Failed to send reply" });
  }
});

module.exports = msgRoutes;
