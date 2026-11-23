
import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PANEL_PATH = path.resolve(__dirname, "../panel.html");
const BASE_URL = "https://sky-admin-bot-web-production.up.railway.app";

const REDIRECT_URI = `${BASE_URL}/auth/discord/callback`;

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.get("/", (req, res) => {
  res.redirect("/panel.html");
});

app.get("/panel.html", (req, res) => {
  res.sendFile(PANEL_PATH);
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/auth/discord", (req, res) => {
  const state = crypto.randomUUID();
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    if (!req.query.code || req.query.state !== req.session.oauthState) {
      return res.status(400).send("OAuth 인증 상태가 올바르지 않습니다.");
    }

    delete req.session.oauthState;

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: process.env.DISCORD_CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code: req.query.code,
          redirect_uri: REDIRECT_URI
        })
      }
    );

    const token = await tokenResponse.json();

    if (!tokenResponse.ok) {
      return res.status(400).send("Discord 토큰 발급에 실패했습니다.");
    }

    const headers = {
      Authorization: `Bearer ${token.access_token}`
    };

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      { headers }
    );

    const guildResponse = await fetch(
      "https://discord.com/api/users/@me/guilds",
      { headers }
    );

    if (!userResponse.ok || !guildResponse.ok) {
      return res.status(400).send("Discord 계정 정보를 가져오지 못했습니다.");
    }

    req.session.user = await userResponse.json();
    req.session.guilds = await guildResponse.json();

    req.session.save((error) => {
      if (error) {
        console.error(error);
        return res.status(500).send("로그인 세션 저장에 실패했습니다.");
      }

      res.redirect("/panel.html");
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("로그인 처리 중 오류가 발생했습니다.");
  }
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: "로그인이 필요합니다."
    });
  }

  res.json({
    user: req.session.user,
    guilds: req.session.guilds || []
  });
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Sky Admin Backend running on port ${port}`);
});
