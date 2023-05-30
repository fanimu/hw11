const express = require('express');
const morgan = require('morgan');
const app = express();
const formidableMiddleware = require('express-formidable');
const todoController = require('./controller/todo.controller');

app.use(formidableMiddleware());
app.use(morgan('combined'));
app.use(todoController);

app.get('/ping', (req, res) => {
  res.json({ ping: true });
});

module.exports = app;
