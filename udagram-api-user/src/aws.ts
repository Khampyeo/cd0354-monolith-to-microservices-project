import AWS = require('aws-sdk');
import { config } from './config/config';

// Configure AWS
const credentials = new AWS.SharedIniFileCredentials({ profile: config.aws_profile });
console.log(config.aws_media_bucket );

AWS.config.credentials = credentials;

export const s3 = new AWS.S3({
  signatureVersion: 'v4',
  region: config.aws_region,
  params: { Bucket: config.aws_media_bucket },
});

// Check connection to S3
s3.headBucket({ Bucket: config.aws_media_bucket }, (err, data) => {
  if (err) {
    console.error(`Failed to connect to S3: ${err.message}`);
  } else {
    console.log(`Successfully connected to S3 bucket: ${config.aws_media_bucket}`);
  }
});

// Generates an AWS signed URL for retrieving objects
export function getGetSignedUrl(key: string): string {
  const signedUrlExpireSeconds = 60 * 5;

  return s3.getSignedUrl('getObject', {
    Bucket: config.aws_media_bucket,
    Key: key,
    Expires: signedUrlExpireSeconds,
  });
}

// Generates an AWS signed URL for uploading objects
export function getPutSignedUrl(key: string): string {
  const signedUrlExpireSeconds = 60 * 5;

  return s3.getSignedUrl('putObject', {
    Bucket: config.aws_media_bucket,
    Key: key,
    Expires: signedUrlExpireSeconds,
  });
}