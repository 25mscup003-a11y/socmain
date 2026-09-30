const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const User = require('./src/models/User.model');
const Company = require('./src/models/Company.model');
const Tenant = require('./src/models/Tenant.model');
const SocCompanyAssignment = require('./src/models/SocCompanyAssignment.model');

const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://localhost:27017/soc_saas';

async function seed() {
  await mongoose.connect(mongoUri);
  console.log('Connected to DB:', mongoUri);

  let tenant = await Tenant.findOne();
  if (!tenant) {
    tenant = await Tenant.create({ name: 'Default Tenant', slug: 'default', type: 'main' });
  }

  let company = await Company.findOne();
  if (!company) {
    company = await Company.create({ name: 'Apex Cybersecurity Ltd', tenantId: tenant._id, status: 'active' });
  }

  const usersToSeed = [
    { email: 'socmanager@example.com', name: 'Alex SOC Manager', role: 'soc_manager' },
    { email: 'l1analyst@example.com', name: 'John L1 Triage Analyst', role: 'l1_analyst' },
    { email: 'l2analyst@example.com', name: 'Sarah L2 Deep Analyst', role: 'l2_analyst' },
    { email: 'l3analyst@example.com', name: 'Michael L3 Threat Hunter', role: 'l3_analyst' },
  ];

  const defaultPassword = 'Password123!';

  for (const u of usersToSeed) {
    let user = await User.findOne({ email: u.email });
    if (!user) {
      user = await User.create({
        name: u.name,
        email: u.email,
        password: defaultPassword,
        role: u.role,
        tenantId: tenant._id,
        companyId: company._id,
        isActive: true,
        accountStatus: 'active',
        isEmailVerified: true,
        forcePasswordReset: false,
      });
      console.log(`Created user ${u.email} (${u.role})`);
    } else {
      user.role = u.role;
      user.password = defaultPassword;
      user.isActive = true;
      user.accountStatus = 'active';
      user.isEmailVerified = true;
      user.forcePasswordReset = false;
      await user.save();
      console.log(`Updated user ${u.email} (${u.role})`);
    }

    // Ensure company assignment exists
    await SocCompanyAssignment.updateOne(
      { userId: user._id, companyId: company._id },
      { $set: { tenantId: tenant._id, active: true } },
      { upsert: true }
    );
  }

  console.log('Seeding complete successfully.');
  await mongoose.disconnect();
}

seed().catch(err => {
  console.error('Seeding error:', err);
  process.exit(1);
});
