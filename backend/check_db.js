const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '.env') });

const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI || process.env.MONGO_URI_LOCAL || process.env.MONGO_URI_CLOUD;

async function check() {
  await mongoose.connect(mongoUri);
  console.log('Connected to DB');
  const db = mongoose.connection.db;
  const collections = await db.listCollections().toArray();
  for (let coll of collections) {
    const count = await db.collection(coll.name).countDocuments();
    console.log(`${coll.name}: ${count}`);
  }
  const alerts = await db.collection('alerts').find({}).limit(1).toArray();
  console.log('Sample alert:', JSON.stringify(alerts, null, 2));
  
  const systems = await db.collection('systems').find({}).limit(1).toArray();
  console.log('Sample system:', JSON.stringify(systems, null, 2));
  
  await mongoose.disconnect();
}
check();
