import { vi, beforeEach } from 'vitest';

// Mock Chrome Storage API
const storageMock = {
  data: {},
  get: vi.fn((keys) => {
    if (Array.isArray(keys)) {
      return Promise.resolve(
        keys.reduce((acc, key) => ({ ...acc, [key]: storageMock.data[key] }), {})
      );
    }
    return Promise.resolve(storageMock.data);
  }),
  set: vi.fn((items) => {
    Object.assign(storageMock.data, items);
    return Promise.resolve();
  }),
  remove: vi.fn((keys) => {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list) {
      delete storageMock.data[key];
    }
    return Promise.resolve();
  }),
  clear: vi.fn(() => {
    storageMock.data = {};
    return Promise.resolve();
  })
};

global.chrome = {
  storage: {
    local: storageMock,
    session: storageMock // Vereinfacht: Session nutzt gleichen Mock
  }
};

// Reset storage vor jedem Test
beforeEach(() => {
  storageMock.clear();
});
