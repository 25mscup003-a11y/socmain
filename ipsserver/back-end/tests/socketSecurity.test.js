const { configureSockets, emitIPSEvent } = require('../src/services/socketService');
const A = '507f1f77bcf86cd799439011';
const B = '507f1f77bcf86cd799439012';

function fixture(auth) {
  process.env.IPS_WEBHOOK_SECRET = 'socket-test-secret';
  const events = {};
  const io = { use: callback => { io.authenticate = callback; }, on: (event, callback) => { io[event] = callback; } };
  configureSockets(io);
  const socket = { handshake: { auth }, data: {}, join: jest.fn(), on: (event, callback) => { events[event] = callback; } };
  const next = jest.fn();
  io.authenticate(socket, next);
  return { io, socket, next, events };
}

test('socket requires a valid service credential', () => {
  expect(fixture({}).next.mock.calls[0][0]).toBeInstanceOf(Error);
  expect(fixture({ secret: 'wrong' }).next.mock.calls[0][0]).toBeInstanceOf(Error);
});

test('company socket cannot join another company or superadmin room', () => {
  const { io, socket, next, events } = fixture({ secret: 'socket-test-secret', companyId: A });
  expect(next.mock.calls[0]).toEqual([]);
  io.connection(socket);
  events['join:company'](B);
  events['join:superadmin']();
  expect(socket.join.mock.calls).toEqual([[`company:${A}`]]);
});

test('emission targets one room union rather than broadcasting to all clients', () => {
  const rooms = [];
  const audience = { to: room => { rooms.push(room); return audience; }, emit: jest.fn() };
  const io = { to: audience.to, emit: jest.fn() };
  emitIPSEvent(io, 'block', { company: A });
  expect(rooms).toEqual(['superadmin', `company:${A}`]);
  expect(audience.emit).toHaveBeenCalledTimes(1);
  expect(io.emit).not.toHaveBeenCalled();
});
