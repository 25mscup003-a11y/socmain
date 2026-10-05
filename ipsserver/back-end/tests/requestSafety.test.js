const { EventEmitter } = require('events');
const { parseBody, MAX_BODY_BYTES } = require('../src/middlewares/bodyParser');

test('UTF-8 characters split across network chunks are preserved', async () => {
  const request = new EventEmitter();
  const body = Buffer.from('{"reason":"नमस्ते"}');
  const result = parseBody(request);
  for (const byte of body) request.emit('data', Buffer.from([byte]));
  request.emit('end');
  await expect(result).resolves.toEqual({ reason: 'नमस्ते' });
});

test('body size uses bytes and drains excess input without accumulating it', async () => {
  const request = new EventEmitter();
  const result = parseBody(request);
  request.emit('data', Buffer.from('é'.repeat(MAX_BODY_BYTES / 2 + 1)));
  request.emit('data', Buffer.alloc(MAX_BODY_BYTES));
  request.emit('end');
  await expect(result).rejects.toMatchObject({ message: 'Payload too large', statusCode: 413 });
});

test.each(['null', '[]', '123', '"string"', '{invalid'])('rejects non-object or invalid JSON: %s', body => {
  const request = new EventEmitter();
  const result = parseBody(request);
  request.emit('data', Buffer.from(body));
  request.emit('end');
  return expect(result).rejects.toThrow();
});

test('aborted request rejects instead of hanging', async () => {
  const request = new EventEmitter();
  const result = parseBody(request);
  request.emit('aborted');
  await expect(result).rejects.toThrow('Request aborted');
});

test('async route failures produce a response instead of an unhandled rejection', async () => {
  jest.resetModules();
  jest.doMock('../src/routes', () => ({ handleRoute: async () => { throw new Error('database unavailable'); } }));
  jest.doMock('../src/utils/logger', () => ({ error: jest.fn() }));
  const { requestHandler } = require('../src/app');
  const req = { method: 'GET', url: '/health', headers: {} };
  const res = { setHeader: jest.fn(), writeHead: jest.fn(), end: jest.fn() };
  await requestHandler(req, res);
  expect(res.writeHead).toHaveBeenCalledWith(500, { 'Content-Type': 'application/json' });
  expect(JSON.parse(res.end.mock.calls[0][0])).toEqual({ ok: false, error: 'Internal server error' });
});
