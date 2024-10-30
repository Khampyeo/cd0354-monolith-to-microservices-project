import { Router, Request, Response } from "express";
import { FeedItem } from "../models/FeedItem";
import { NextFunction } from "connect";
import * as jwt from "jsonwebtoken";
import * as AWS from "../../../../aws";
import * as c from "../../../../config/config";

const router: Router = Router();

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

// Get all feed items
router.get("/", async (req: Request, res: Response) => {
  try {
    console.log("Fetching all feed items...");
    const items = await FeedItem.findAndCountAll({ order: [["id", "DESC"]] });
    items.rows.map((item) => {
      if (item.url) {
        item.url = AWS.getGetSignedUrl(item.url);
      }
    });
    console.log("Feed items fetched successfully.");
    res.send(items);
  } catch (error) {
    console.error("Error fetching feed items:", error);
    res.status(500).send({ message: "Error fetching feed items." });
  }
});

// Get a feed resource
router.get("/:id", async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    console.log(`Fetching feed item with id: ${id}...`);
    const item = await FeedItem.findByPk(id);
    if (!item) {
      console.error(`Feed item with id ${id} not found.`);
      return res.status(404).send({ message: "Feed item not found." });
    }
    console.log(`Feed item with id: ${id} fetched successfully.`);
    res.send(item);
  } catch (error) {
    console.error("Error fetching feed item:", error);
    res.status(500).send({ message: "Error fetching feed item." });
  }
});

// Get a signed url to put a new item in the bucket
router.get(
  "/signed-url/:fileName",
  requireAuth,
  async (req: Request, res: Response) => {
    const { fileName } = req.params;
    console.log(`Generating signed URL for file: ${fileName}...`);
    try {
      const url = AWS.getPutSignedUrl(fileName);
      console.log(`Signed URL generated: ${url}`);
      res.status(201).send({ url: url });
    } catch (error) {
      console.error("Error generating signed URL:", error);
      res.status(500).send({ message: "Error generating signed URL." });
    }
  }
);

// Create feed with metadata
router.post("/", requireAuth, async (req: Request, res: Response) => {
  const caption = req.body.caption;
  const fileName = req.body.url; // same as S3 key name

  if (!caption) {
    console.error("Caption is required or malformed.");
    return res
      .status(400)
      .send({ message: "Caption is required or malformed." });
  }

  if (!fileName) {
    console.error("File URL is required.");
    return res.status(400).send({ message: "File URL is required." });
  }

  console.log("Creating a new feed item...");
  try {
    const item = new FeedItem({
      caption: caption,
      url: fileName,
    });

    const savedItem = await item.save();
    console.log("Feed item saved successfully.");

    savedItem.url = AWS.getGetSignedUrl(savedItem.url);
    console.log("Signed URL for saved item generated.");
    res.status(201).send(savedItem);
  } catch (error) {
    console.error("Error creating feed item:", error);
    res.status(500).send({ message: "Error creating feed item." });
  }
});

export const FeedRouter: Router = router;
