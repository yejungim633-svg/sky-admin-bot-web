import express from "express";
import session from "express-session";

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: "auto",
    httpOnly: true,
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.get("/", (req, res) => {
  res.send("Sky Admin Backend is running.");
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Sky Admin Backend running on port ${port}`);
});
