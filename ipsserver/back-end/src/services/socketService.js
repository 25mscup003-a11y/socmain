const { validSecret, validCompany } = require('../middlewares/auth');

function configureSockets(io) {
  io.use((socket, next) => {
    const auth = socket.handshake.auth || {};
    if (!validSecret(auth.secret || socket.handshake.headers?.['x-webhook-secret'])) {
      return next(new Error('Unauthorized'));
    }
    if (auth.companyId && !validCompany(auth.companyId)) return next(new Error('Invalid company_id'));
    socket.data.companyId = auth.companyId ? auth.companyId.toLowerCase() : null;
    next();
  });
  io.on('connection', socket => {
    const company = socket.data.companyId;
    socket.join(company ? `company:${company}` : 'superadmin');
    socket.on('join:company', requested => {
      if (validCompany(requested) && (!company || requested.toLowerCase() === company)) {
        socket.join(`company:${requested.toLowerCase()}`);
      }
    });
    socket.on('join:superadmin', () => { if (!company) socket.join('superadmin'); });
  });
}

function emitIPSEvent(io, event, data) {
  if (!io) return;
  const company = data?.company || data?.companyId;
  // Room unions avoid duplicate deliveries to clients in both rooms.
  let audience = io.to('superadmin');
  if (validCompany(String(company || ''))) audience = audience.to(`company:${String(company).toLowerCase()}`);
  audience.emit(`ips:${event}`, data);
}

module.exports = { configureSockets, emitIPSEvent };
