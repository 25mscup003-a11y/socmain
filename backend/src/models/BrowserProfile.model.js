/**
 * BrowserProfile Model
 * Rich browser capabilities snapshot: hardware, fonts, canvas, audio fingerprints.
 */
const mongoose = require('mongoose');

const BrowserProfileSchema = new mongoose.Schema({
  browserId:          { type: String, required: true, unique: true, index: true },
  browserFingerprint: { type: String, index: true },
  hardwareFingerprint:{ type: String },
  networkFingerprint: { type: String },

  // Browser details
  browser:        { type: String },
  browserVersion: { type: String },
  engine:         { type: String },
  os:             { type: String },
  osVersion:      { type: String },
  platform:       { type: String },
  deviceType:     { type: String, enum: ['desktop', 'mobile', 'tablet', 'unknown'], default: 'unknown' },

  // Hardware signals
  cpuCores:       { type: Number },
  memoryGb:       { type: Number },
  screenWidth:    { type: Number },
  screenHeight:   { type: Number },
  colorDepth:     { type: Number },
  touchPoints:    { type: Number },
  gpuRenderer:    { type: String },
  gpuVendor:      { type: String },

  // Behavioral signals
  languages:      [{ type: String }],
  timezone:       { type: String },
  timezoneOffset: { type: Number },
  canvasHash:     { type: String },
  audioHash:      { type: String },
  webglHash:      { type: String },

  // Plugin/features
  cookiesEnabled: { type: Boolean },
  javaEnabled:    { type: Boolean },
  doNotTrack:     { type: Boolean },
  adBlocker:      { type: Boolean },
  headlessBrowser:{ type: Boolean },

  // Tracking
  firstSeenAt:    { type: Date, default: Date.now },
  lastSeenAt:     { type: Date, default: Date.now },
  sessionCount:   { type: Number, default: 1 },
}, { timestamps: true });

module.exports = mongoose.model('BrowserProfile', BrowserProfileSchema);
