const { MongoClient } = require('mongodb');

async function seedData() {
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error('MONGO_URI environment variable is required');

  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db('soc4_ips');
    console.log('🌱 Seeding test data...');

    const threatResult = await db.collection('threat_intel').insertMany([
      { ip: '192.168.1.100', domain: 'malicious.com', attackType: 'SQL Injection', threatLevel: 'high', confidence: 0.95, score: 85, reason: 'Known malicious IP', source: 'webhook', company: 'acme-corp', ts: new Date() },
      { ip: '10.0.0.50', domain: 'phishing-site.org', attackType: 'Phishing', threatLevel: 'high', confidence: 0.90, score: 80, reason: 'Phishing campaign detected', source: 'webhook', company: 'tech-labs', ts: new Date() },
      { ip: '172.16.0.25', domain: 'botnet.net', attackType: 'DDoS', threatLevel: 'critical', confidence: 0.99, score: 95, reason: 'Botnet command & control', source: 'webhook', company: 'global-trade', ts: new Date() },
    ]);
    console.log(`✅ Inserted ${threatResult.insertedCount} threats`);

    const blockResult = await db.collection('firewall_blocks').insertMany([
      { blockKey: 'ip-192.168.1.100', ip: '192.168.1.100', status: 'blocked', reason: 'Malicious activity detected', direction: 'both', company: 'acme-corp', ts: new Date() },
      { blockKey: 'domain-malicious.com', domain: 'malicious.com', status: 'blocked', reason: 'Known phishing domain', direction: 'inbound', company: 'tech-labs', ts: new Date() },
      { blockKey: 'ip-172.16.0.25', ip: '172.16.0.25', status: 'blocked', reason: 'Botnet C2 server', direction: 'both', company: 'global-trade', ts: new Date() },
    ]);
    console.log(`✅ Inserted ${blockResult.insertedCount} firewall blocks`);

    const attackResult = await db.collection('attack_events').insertMany([
      { srcIp: '192.168.1.100', attackType: 'SQL Injection', threatLevel: 'high', score: 85, direction: 'inbound', autoBlocked: true, company: 'acme-corp', ts: new Date() },
      { srcIp: '10.0.0.50', attackType: 'Phishing', threatLevel: 'high', score: 80, direction: 'inbound', autoBlocked: true, company: 'tech-labs', ts: new Date() },
      { srcIp: '172.16.0.25', attackType: 'DDoS', threatLevel: 'critical', score: 95, direction: 'inbound', autoBlocked: true, company: 'global-trade', ts: new Date() },
    ]);
    console.log(`✅ Inserted ${attackResult.insertedCount} attack events`);
    console.log('🎉 Data seeding complete!');
  } finally {
    await client.close();
  }
}

seedData().catch(console.error);
