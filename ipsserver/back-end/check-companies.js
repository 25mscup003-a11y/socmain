const { MongoClient } = require('mongodb');

async function checkCompanies() {
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error('MONGO_URI environment variable is required');

  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db('soc4_ips');
    console.log('========================================');
    console.log('📋 COMPANY DETAILS FROM DATABASE');
    console.log('========================================\n');

    const companies = await db.collection('companies').find({}).toArray();
    console.log(`Total Companies Registered: ${companies.length}\n`);
    companies.forEach((company, idx) => {
      console.log(`${idx + 1}. ${company.name}`);
      console.log(`   ID: ${company.companyId}`);
      console.log(`   Email: ${company.email || 'Not provided'}`);
      console.log(`   Country: ${company.country || 'Not provided'}`);
      console.log(`   Industry: ${company.industry || 'Not provided'}`);
      console.log(`   Status: ${company.active ? '✅ Active' : '❌ Inactive'}`);
      console.log(`   Registered: ${company.registeredAt}`);
      console.log('');
    });

    console.log('========================================');
    console.log('⚠️  THREAT COUNT BY COMPANY');
    console.log('========================================\n');
    const threatStats = await db.collection('threat_intel').aggregate([
      { $group: { _id: '$company', count: { $sum: 1 }, avgScore: { $avg: '$score' } } },
      { $sort: { count: -1 } },
    ]).toArray();
    threatStats.forEach((stat) => {
      console.log(`${stat._id}: ${stat.count} threats (avg score: ${stat.avgScore?.toFixed(2) || 'N/A'})`);
    });

    console.log('\n========================================');
    console.log('🔒 BLOCKED IPs BY COMPANY');
    console.log('========================================\n');
    const blockStats = await db.collection('firewall_blocks').aggregate([
      { $match: { status: 'blocked' } },
      { $group: { _id: '$company', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]).toArray();
    blockStats.forEach((stat) => {
      console.log(`${stat._id || 'No Company'}: ${stat.count} blocked IPs`);
    });
  } finally {
    await client.close();
  }
}

checkCompanies().catch(console.error);
