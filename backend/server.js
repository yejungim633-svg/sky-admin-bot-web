
import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BASE_URL = "https://sky-admin-bot-web-production.up.railway.app";
const REDIRECT_URI = `${BASE_URL}/auth/discord/callback`;

app.set("trust proxy", 1);
app.use(express.json());

const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/"
};

app.use(session({
  name: "sky.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    ...cookieOptions,
    maxAge: 86400000
  }
}));

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");
    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

app.get("/", (req, res) => {
  res.redirect("/panel.html");
});

app.get("/panel.html", (req, res) => {
  res.sendFile(path.join(__dirname, "panel.html"));
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// 디스코드 로그인 시작
app.get("/auth/discord", (req, res) => {
  if (
    !process.env.DISCORD_CLIENT_ID ||
    !process.env.DISCORD_CLIENT_SECRET ||
    !process.env.SESSION_SECRET
  ) {
    return res.status(500).send("Railway 환경변수를 확인해 주세요.");
  }

  const state = crypto.randomUUID();

  res.cookie("sky.oauth_state", state, {
    ...cookieOptions,
    maxAge: 600000
  });

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// 디스코드 로그인 승인 처리
app.get("/auth/discord/callback", async (req, res) => {
  try {
    if (req.query.error) {
      res.clearCookie("sky.oauth_state", cookieOptions);
      return res.status(400).send("디스코드 로그인이 취소되었습니다.");
    }

    const code = req.query.code;
    const receivedState = req.query.state;
    const savedState = getCookie(req, "sky.oauth_state");

    if (
      typeof code !== "string" ||
      typeof receivedState !== "string" ||
      !savedState ||
      receivedState !== savedState
    ) {
      res.clearCookie("sky.oauth_state", cookieOptions);
      return res.status(400).send(
        "로그인 인증 오류: 인증 상태가 일치하지 않습니다. 관리 패널에서 다시 로그인해 주세요."
      );
    }

    res.clearCookie("sky.oauth_state", cookieOptions);

    // 액세스 토큰 요청
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
          code,
          redirect_uri: REDIRECT_URI
        })
      }
    );

    const token = await tokenResponse.json();

    if (!tokenResponse.ok || !token.access_token) {
      console.error("Discord token error:", token.error || token.message);
      return res.status(400).send("Discord 토큰 발급 실패");
    }

    const headers = {
      Authorization: `Bearer ${token.access_token}`
    };

    // 사용자 및 서버 목록 가져오기
    const [userResponse, guildResponse] = await Promise.all([
      fetch("https://discord.com/api/users/@me", { headers }),
      fetch("https://discord.com/api/users/@me/guilds", { headers })
    ]);

    if (!userResponse.ok || !guildResponse.ok) {
      return res.status(400).send("Discord 정보 불러오기 실패");
    }

    const user = await userResponse.json();
    const guilds = await guildResponse.json();

    // 새 세션 생성
    req.session.regenerate(error => {
      if (error) {
        console.error("Session regenerate error:", error);
        return res.status(500).send("로그인 세션 생성 실패");
      }

      req.session.user = user;
      req.session.guilds = guilds;

      req.session.save(saveError => {
        if (saveError) {
          console.error("Session save error:", saveError);
          return res.status(500).send("로그인 세션 저장 실패");
        }

        res.redirect("/panel.html");
      });
    });

  } catch (error) {
    console.error("OAuth callback error:", error);
    res.status(500).send("로그인 처리 오류");
  }
});

// 로그인 사용자 정보
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

// 로그아웃
app.post("/auth/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({ success: false });
    }

    res.clearCookie("sky.sid", cookieOptions);
    res.json({ success: true });
  });
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Sky Admin Bot running on ${port}`);
});
