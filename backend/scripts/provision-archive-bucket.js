require('dotenv').config();
const { S3Client, HeadBucketCommand, CreateBucketCommand } = require('@aws-sdk/client-s3');

async function run() {
  const bucket = process.env.ARCHIVE_S3_BUCKET;
  if (!bucket) throw new Error('ARCHIVE_S3_BUCKET is required');
  const options = { region: process.env.ARCHIVE_S3_REGION || 'us-east-1' };
  if (process.env.ARCHIVE_S3_ENDPOINT) options.endpoint = process.env.ARCHIVE_S3_ENDPOINT;
  if (process.env.ARCHIVE_S3_FORCE_PATH_STYLE === 'true') options.forcePathStyle = true;
  const client = new S3Client(options);
  try {
    await client.send(new HeadBucketCommand({ Bucket: bucket }));
    console.log(JSON.stringify({ bucket, created: false }));
  } catch (error) {
    const missing = error?.$metadata?.httpStatusCode === 404 || ['NotFound', 'NoSuchBucket'].includes(error?.name);
    if (!missing) throw error;
    await client.send(new CreateBucketCommand({ Bucket: bucket }));
    console.log(JSON.stringify({ bucket, created: true }));
  }
  client.destroy();
}

if (require.main === module) run().catch(error => {
  console.error(error.message);
  process.exit(1);
});

module.exports = { run };
