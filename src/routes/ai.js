const express = require("express");
const aiRoute = express.Router();
const axios = require("axios");

const API_KEY = process.env.API_KEY;

// 🔥 Generate AI response (no database used)
aiRoute.post("/gemini", async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) {
      return res.status(400).json({ message: "Prompt is required" });
    }

    // 🧠 Gemini API Call
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${API_KEY}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const aiResponse =
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "⚠️ No response from Gemini";

    // ✅ Send AI response to frontend
    res.status(200).json({ response: aiResponse });
  } catch (err) {
    console.error("Gemini API Error:", err.message);
    res
      .status(500)
      .json({ message: "Failed to get response from Gemini", error: err.message });
  }
});

module.exports = aiRoute;
