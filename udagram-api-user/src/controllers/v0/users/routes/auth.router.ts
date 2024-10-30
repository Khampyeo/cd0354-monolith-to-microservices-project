import { Router, Request, Response } from "express";
import { User } from "../models/User";
import * as c from "../../../../config/config";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { NextFunction } from "connect";
import * as EmailValidator from "email-validator";

const router: Router = Router();

async function generatePassword(plainTextPassword: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(plainTextPassword, salt);
}

async function comparePasswords(
  plainTextPassword: string,
  hash: string
): Promise<boolean> {
  return await bcrypt.compare(plainTextPassword, hash);
}

function generateJWT(user: User): string {
  console.log(`Generating JWT for user: ${user.email}`);
  return jwt.sign(user.short(), c.config.jwt.secret);
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  console.log("Authenticating request...");

  if (!req.headers || !req.headers.authorization) {
    console.error("No authorization headers found.");
    return res.status(401).send({ message: "No authorization headers." });
  }

  const tokenBearer = req.headers.authorization.split(" ");
  if (tokenBearer.length !== 2) {
    console.error("Malformed token.");
    return res.status(401).send({ message: "Malformed token." });
  }

  const token = tokenBearer[1];
  return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      console.error("Failed to authenticate token.", err);
      return res
        .status(500)
        .send({ auth: false, message: "Failed to authenticate." });
    }
    console.log("Token authenticated successfully.");
    return next();
  });
}

router.get(
  "/verification",
  requireAuth,
  async (req: Request, res: Response) => {
    console.log("Verification successful.");
    return res.status(200).send({ auth: true, message: "Authenticated." });
  }
);

router.post("/login", async (req: Request, res: Response) => {
  const email = req.body.email;
  const password = req.body.password;

  console.log(`Attempting login for email: ${email}`);

  if (!email || !EmailValidator.validate(email)) {
    console.error("Invalid or missing email.");
    return res
      .status(400)
      .send({ auth: false, message: "Email is required or malformed." });
  }

  if (!password) {
    console.error("Password is required.");
    return res
      .status(400)
      .send({ auth: false, message: "Password is required." });
  }

  const user = await User.findByPk(email);
  if (!user) {
    console.error("User not found.");
    return res
      .status(401)
      .send({ auth: false, message: "User was not found." });
  }

  const authValid = await comparePasswords(password, user.passwordHash);

  if (!authValid) {
    console.error("Invalid password.");
    return res
      .status(401)
      .send({ auth: false, message: "Password was invalid." });
  }

  const token = generateJWT(user);
  console.log(`User ${email} logged in successfully.`);
  res.status(200).send({ auth: true, token: token, user: user.short() });
});

router.post("/", async (req: Request, res: Response) => {
  const email = req.body.email;
  const plainTextPassword = req.body.password;

  console.log(`Registering new user with email: ${email}`);

  if (!email || !EmailValidator.validate(email)) {
    console.error("Invalid or missing email.");
    return res
      .status(400)
      .send({ auth: false, message: "Email is missing or malformed." });
  }

  if (!plainTextPassword) {
    console.error("Password is required.");
    return res
      .status(400)
      .send({ auth: false, message: "Password is required." });
  }

  const user = await User.findByPk(email);
  if (user) {
    console.error("User already exists.");
    return res
      .status(422)
      .send({ auth: false, message: "User already exists." });
  }

  try {
    const generatedHash = await generatePassword(plainTextPassword);

    const newUser = new User({
      email: email,
      passwordHash: generatedHash,
    });

    const savedUser = await newUser.save();
    console.log(`User ${email} registered successfully.`);

    const token = generateJWT(savedUser);
    res.status(201).send({ token: token, user: savedUser.short() });
  } catch (error) {
    console.error("Error registering new user:", error);
    res.status(500).send({ message: "Error registering new user." });
  }
});

router.get("/", async (req: Request, res: Response) => {
  console.log("Authentication root route accessed.");
  res.send("auth");
});

export const AuthRouter: Router = router;
