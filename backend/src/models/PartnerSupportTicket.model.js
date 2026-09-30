const mongoose = require('mongoose');

const PartnerSupportTicketSchema = new mongoose.Schema({
  ticketId: { type: String, required: true, unique: true, trim: true },
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', required: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  category: { type: String, required: true, trim: true },
  priority: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'], default: 'Medium' },
  subject: { type: String, required: true, trim: true },
  description: { type: String, required: true, trim: true },
  payment: {
    transactionId: { type: String, default: '' },
    paymentDate: { type: String, default: '' },
    amount: { type: Number, default: 0 },
    companyName: { type: String, default: '' },
  },
  attachments: {
    screenshot: { type: String, default: '' },
    screenshotName: { type: String, default: '' },
    screenshotDataUrl: { type: String, default: '' },
    invoice: { type: String, default: '' },
    documents: { type: String, default: '' },
  },
  solution: { type: String, default: '' },
  resolvedAt: { type: Date, default: null },
  messages: [{
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderName: { type: String, required: true },
    senderRole: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  status: { type: String, enum: ['Open', 'In Progress', 'Resolved', 'Closed'], default: 'Open' },
}, { timestamps: true });

module.exports = mongoose.model('PartnerSupportTicket', PartnerSupportTicketSchema);
