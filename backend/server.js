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
app.use(express.json({ limit: "64kb" }));

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
  cookie: { ...cookieOptions, maxAge: 86400000 }
}));

function getCookie(req, name) {
  for (const item of (req.headers.cookie || "").split(";")) {
    const index = item.indexOf("=");
    if (index === -1) continue;
    if (item.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(item.slice(index + 1).trim());
      } catch {
        return item.slice(index + 1).trim();
      }
    }
  }
  return null;
}

function hasAdminPermission(guild) {
  if (guild.owner === true) return true;
  try {
    return (BigInt(guild.permissions || "0") & 8n) === 8n;
  } catch {
    return false;
  }
}

function getAdminGuilds(req) {
  return (req.session.guilds || []).filter(hasAdminPermission);
}

app.get("/", (req, res) => res.redirect("/panel.html"));

app.get("/panel.html", (req, res) => {
  res.sendFile(path.join(__dirname, "panel.html"));
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get("/auth/discord", (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID ||
      !process.env.DISCORD_CLIENT_SECRET ||
      !process.env.SESSION_SECRET) {
    return res.status(500).send("Railway 환경변수를 확인해 주세요.");
  }

  const state = crypto.randomUUID();
  res.cookie("sky.oauth_state", state, { ...cookieOptions, maxAge: 600000 });

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
      return res.status(400).send("로그인 인증 오류. 다시 로그인해 주세요.");
    }

    res.clearCookie("sky.oauth_state", cookieOptions);

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI
      })
    });

    const token = await tokenResponse.json();

    if (!tokenResponse.ok || !token.access_token) {
      console.error("Discord token error:", token);
      return res.status(400).send("Discord 토큰 발급 실패");
    }

    const headers = {
      Authorization: `Bearer ${token.access_token}`
    };

    const [userResponse, guildResponse] = await Promise.all([
      fetch("https://discord.com/api/users/@me", { headers }),
      fetch("https://discord.com/api/users/@me/guilds", { headers })
    ]);

    if (!userResponse.ok || !guildResponse.ok) {
      return res.status(400).send("Discord 정보 불러오기 실패");
    }

    const user = await userResponse.json();
    const guilds = await guildResponse.json();

    req.session.regenerate(error => {
      if (error) {
        console.error(error);
        return res.status(500).send("로그인 세션 생성 실패");
      }

      req.session.user = user;
      req.session.guilds = guilds;
      req.session.selectedGuildId = null;

      req.session.save(saveError => {
        if (saveError) {
          console.error(saveError);
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

app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }

  const adminGuilds = getAdminGuilds(req);
  const selectedGuild =
    adminGuilds.find(guild => guild.id === req.session.selectedGuildId) || null;

  res.json({
    user: req.session.user,
    guilds: adminGuilds,
    selectedGuild
  });
});

app.post("/api/select-server", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }

  const guildId = req.body?.guildId;

  if (typeof guildId !== "string") {
    return res.status(400).json({ error: "서버 선택 정보가 올바르지 않습니다." });
  }

  const guild = getAdminGuilds(req).find(item => item.id === guildId);

  if (!guild) {
    return res.status(403).json({
      error: "관리자 권한이 있는 서버만 선택할 수 있습니다."
    });
  }

  req.session.selectedGuildId = guild.id;

  req.session.save(error => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "서버 선택 저장 실패" });
    }

    res.json({
      success: true,
      guild: {
        id: guild.id,
        name: guild.name,
        icon: guild.icon
      }
    });
  });
});

app.post("/api/deselect-server", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }

  req.session.selectedGuildId = null;

  req.session.save(error => {
    if (error) {
      return res.status(500).json({ error: "저장 실패" });
    }

    res.json({ success: true });
  });
});

async function proxyBotApi(req, res, endpoint) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Discord 로그인이 필요합니다."
    });
  }

  const guildId = req.session.selectedGuildId;

  if (!guildId) {
    return res.status(400).json({
      error: "먼저 관리할 서버를 선택하세요."
    });
  }

  const allowedGuild =
    getAdminGuilds(req).find(guild => guild.id === guildId);

  if (!allowedGuild) {
    return res.status(403).json({
      error: "선택한 서버의 관리자 권한을 확인할 수 없습니다."
    });
  }

  const apiBase = (process.env.BOT_API_URL || "").replace(/\/+$/, "");
  const apiKey = process.env.BOT_API_KEY || "";

  if (!apiBase || !apiKey) {
    return res.status(503).json({
      error: "봇 API 연결 설정이 필요합니다. Railway의 BOT_API_URL과 BOT_API_KEY를 확인하세요."
    });
  }

  try {
    const query =
      req.method === "GET" && req.originalUrl.includes("?")
        ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
        : "";

    const upstream = await fetch(
      `${apiBase}/panel/${endpoint}${query}`,
      {
        method: req.method,
        headers: {
          "Content-Type": "application/json",
          "X-Sky-Panel-Key": apiKey,
          "X-Discord-User-ID": String(req.session.user.id),
          "X-Guild-ID": String(guildId)
        },
        ...(req.method === "POST"
          ? { body: JSON.stringify(req.body || {}) }
          : {})
      }
    );

    const raw = await upstream.text();

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = {
        error: raw || "봇 API 응답을 해석할 수 없습니다."
      };
    }

    return res.status(upstream.status).json(data);
  } catch (error) {
    console.error("Bot API proxy error:", error);

    return res.status(502).json({
      error: "하늘봇 서비스에 연결하지 못했습니다. 봇 서비스 상태와 BOT_API_URL을 확인하세요."
    });
  }
}

app.get("/api/panel/overview", (req, res) =>
  proxyBotApi(req, res, "overview")
);

app.get("/api/panel/logs", (req, res) =>
  proxyBotApi(req, res, "logs")
);

app.get("/api/panel/roles", (req, res) =>
  proxyBotApi(req, res, "roles")
);

app.get("/api/panel/tickets", (req, res) =>
  proxyBotApi(req, res, "tickets")
);

app.get("/api/panel/security", (req, res) =>
  proxyBotApi(req, res, "security")
);

app.post("/api/panel/security", (req, res) =>
  proxyBotApi(req, res, "security")
);

app.get("/api/panel/settings", (req, res) =>
  proxyBotApi(req, res, "settings")
);

app.post("/api/panel/settings", (req, res) =>
  proxyBotApi(req, res, "settings")
);

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
