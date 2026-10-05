const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  countryCode: { type: String, required: true, unique: true },
  ipv4: [String],
  ipv6: [String],
  fetchedAt: { type: Date, required: true },
});
module.exports = mongoose.models.CountryNetwork || mongoose.model('CountryNetwork', schema);
