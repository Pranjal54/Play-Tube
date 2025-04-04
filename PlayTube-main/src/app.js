import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";

const app = express();
//https://play-tube-frontend.vercel.app
app.use(
  cors({
    origin: [
      "https://play-tube-sepia.vercel.app",
      "https://play-tube-9tknbo209-pranjal54s-projects.vercel.app/",
      "http://localhost:5173",
      "http://localhost:4173"
    ],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  })
);

// origin: process.env.CORS_ORIGIN,

app.use(express.json({ limit: "99mb" }));
app.use(express.urlencoded({ extended: true, limit: "99mb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(morgan("dev"));

//import Routes
import userRouter from "./routes/user.routes.js"; 
import videoRouter from "./routes/video.routes.js";
import tweetRouter from "./routes/tweet.routes.js";
import subscriptionRouter from "./routes/subscription.routes.js";
import playlistRouter from "./routes/playlist.routes.js";
import commentRouter from "./routes/comment.routes.js";
import likeRouter from "./routes/like.routes.js";
import dashboardRouter from "./routes/dashboard.routes.js";
import healthcheckRouter from "./routes/healthcheck.routes.js";
import aboutRouter from "./routes/about.routes.js";

app.get("/", (_req, res) => res.send("Backend of YouTube+Twitter by Pranjal"));

// http://localhost:8000/api/v1/healthcheck/routes
app.use("/api/v1/healthcheck", healthcheckRouter);

// http://localhost:8000/api/v1/users/routes
app.use("/api/v1/users", userRouter);

// http://localhost:8000/api/v1/videos/routes
app.use("/api/v1/videos", videoRouter);

// http://localhost:8000/api/v1/tweets/routes
app.use("/api/v1/tweets", tweetRouter);

// http://localhost:8000/api/v1/subscription/routes
app.use("/api/v1/subscription", subscriptionRouter);

// http://localhost:8000/api/v1/playlist/routes
app.use("/api/v1/playlist", playlistRouter);

// http://localhost:8000/api/v1/comment/routes
app.use("/api/v1/comment", commentRouter);

// http://localhost:8000/api/v1/like/routes
app.use("/api/v1/like", likeRouter);

// http://localhost:8000/api/v1/dashboard/routes
app.use("/api/v1/dashboard", dashboardRouter);

// http://localhost:8000/api/v1/about/user
app.use("/api/v1/about/user/", aboutRouter);

export  { app };
