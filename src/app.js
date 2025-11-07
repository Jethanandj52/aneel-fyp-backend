require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { dbConnected } = require("./config/dataBase");

// Import all route files
const { routes } = require("./routes/auth");
const networkRouter = require("./routes/network");
const valunRouter = require("./routes/valun");
const portRouter = require("./routes/port");
const sslRouter = require("./routes/ssl");
const msgRoutes = require("./routes/msg");
const aiRoute = require("./routes/ai");
const historyRoute = require("./routes/historyRoute");
const sslHistoryRoutes = require("./routes/sslHistory");
const portHistoryRouter = require("./routes/portHistory");
const valunHistory = require("./routes/valunHistory");
const phishRoutes = require("./routes/phish"); // ✅ Phishing detection route

// Initialize app
const app = express();

// ✅ Middleware setup
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cookieParser());

// ✅ CORS setup — allow frontend communication
app.use(
  cors({
    origin: "http://localhost:3000", // your React frontend
    credentials: true,
  })
);

// ✅ Database Connection
dbConnected()
  .then(() => console.log("✅ Connected to MongoDB successfully"))
  .catch((err) => console.error("❌ Could not connect to MongoDB:", err));

// ✅ API Routes
app.use("/auth", routes);
app.use("/network", networkRouter);
app.use("/vuln", valunRouter);
app.use("/port", portRouter);
app.use("/ssl", sslRouter);
app.use("/msg", msgRoutes);
app.use("/ai", aiRoute);
app.use("/history", historyRoute);
app.use("/sslhistory", sslHistoryRoutes);
app.use("/portHistory", portHistoryRouter);
app.use("/valunHistory", valunHistory);
app.use("/phish", phishRoutes); // ✅ New phishing detection route

// ✅ Default Route
app.get("/", (req, res) => {
  res.send("🚀 Backend server running successfully!");
});

// ✅ Start Server
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//   console.log(`🚀 Server is running on port ${PORT}`);
// });
module.exports = app;