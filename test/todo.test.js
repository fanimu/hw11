const request = require('supertest');
const assert = require('assert');
const dotenv = require('dotenv');
const todoService = require('../service/todo.service');
dotenv.config();

const app = require('../app');

describe('GET /ping', () => {
  it('should return 200 ok', () => {
    request(app)
      .get('/ping')
      .expect('Content-Type', 'application/json; charset=utf-8')
      .expect(200)
      .end(function (err, res) {
        if (err) throw err;
      });
  });
});

// GET /api/todos
describe('GET /api/todos', () => {
  it('should return 200 ok', (done) => {
    request(app).get('/api/todos').expect('Content-Type', 'application/json; charset=utf-8').expect(200, done);
  });
});

// GET /api/todos/:id
// write your code here
describe('GET /api/todos/:id', () => {
  it('should return 200 ok', (done) => {
    request(app).post('/api/todos').set({ title: 'Lorem', description: 'Lorem ipsum dolor sit amet, consectetur adipisicing' }).expect('Content-Type', 'application/json; charset=utf-8').expect(201, done);

    request(app).get(`/api/todos/1`).expect('Content-Type', 'application/json; charset=utf-8').expect(200, done);
  });

  it('should return 404 not found', (done) => {
    request(app).get(`/api/todos/2000`).expect('Content-Type', 'application/json; charset=utf-8').expect(404, done);
  });
});

// POST api/todos
// Test scenario
describe('POST /api/todos', () => {
  // Test case
  it('should return 201 ok', (done) => {
    request(app).post('/api/todos').set({ title: 'Lorem', description: 'Lorem ipsum dolor sit amet, consectetur adipisicing' }).expect('Content-Type', 'application/json; charset=utf-8').expect(201, done);
  });
});

// PUT /api/todos/:id
// write your code here
describe('PUT /api/todos/:id', () => {
  it('should return 200 ok', (done) => {
    request(app).put('/api/todos').set({ title: 'Lorem', description: 'Lorem ipsum dolor sit amet, consectetur adipisicing' }).expect('Content-Type', 'application/json; charset=utf-8').expect(201, done);

    request(app).get(`/api/todos/1`).expect('Content-Type', 'application/json; charset=utf-8').expect(200, done);
  });

  it('should return 404 not found', (done) => {
    request(app).get(`/api/todos/2000`).expect('Content-Type', 'application/json; charset=utf-8').expect(404, done);
  });
});

// DELETE /api/todos/:id
// write your code here
describe('DELETE /api/todos/:id', () => {
  it('should return 200 ok', (done) => {
    request(app).delete('/api/todos').set({ title: 'Lorem', description: 'Lorem ipsum dolor sit amet, consectetur adipisicing' }).expect('Content-Type', 'application/json; charset=utf-8').expect(201, done);

    request(app).get(`/api/todos/1`).expect('Content-Type', 'application/json; charset=utf-8').expect(200, done);
  });

  it('should return 404 not found', (done) => {
    request(app).get(`/api/todos/2000`).expect('Content-Type', 'application/json; charset=utf-8').expect(404, done);
  });
});
