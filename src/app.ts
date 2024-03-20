// ChatGPT Snyk

import express, { Request, Response } from "express";
import helmet from "helmet";
import logger from "morgan";
import * as path from "path";
import rateLimit from "express-rate-limit";
import {
  errorHandler,
  errorNotFoundHandler,
} from "./middleware/error.middleware.js";
import {
  authenticatedUser,
  currentSession,
} from "./middleware/auth.middleware.js";
import { ExpressAuth } from "@auth/express";
import { authConfig } from "./config/auth.config.js";
import * as pug from "pug";

// Define a custom interface to extend the Express Request object
interface CustomRequest extends Request {
  csrfToken?: () => string; // Define csrfToken property
}

// Create Express server
export const app = express();

// Express configuration
app.set("port", process.env.PORT || 3000);

// Set up views engine and path
// @ts-expect-error (See https://stackoverflow.com/questions/45342307/error-cannot-find-module-pug)
app.engine("pug", pug.__express);
app.set("views", path.join(__dirname, "../views"));
app.set("view engine", "pug");

// Trust Proxy for Proxies (Heroku, Render.com, etc)
// https://stackoverflow.com/questions/40459511/in-express-js-req-protocol-is-not-picking-up-https-for-my-secure-link-it-alwa
app.enable("trust proxy");

app.use(logger("dev"));

// Secure Express app by disabling X-Powered-By header and setting other security headers
app.use(helmet());

// Parse incoming requests data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set session in res.locals
app.use(currentSession);

// Set up ExpressAuth to handle authentication
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});

app.use("/api/auth/*", limiter, ExpressAuth(authConfig));

// Routes
app.get("/protected", async (_req, res) => {
  res.render("protected", { session: res.locals.session });
});

app.get(
  "/api/protected",
  authenticatedUser,
  async (req: CustomRequest, res: Response) => {
    res.json(res.locals.session);
  }
);

app.get("/", async (req: CustomRequest, res: Response) => {
  res.render("index", {
    title: "Express Auth Example",
    user: res.locals.session?.user,
    csrfToken: req.csrfToken ? req.csrfToken() : "", // Use csrfToken if it exists
  });
});

// Error handlers
app.use(errorNotFoundHandler);
app.use(errorHandler);
