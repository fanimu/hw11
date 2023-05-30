const express = require('express');
const router = express.Router();
const todoService = require('..//service/todo.service');

router.get('/api/todos', async (req, res, next) => {
  const todos = await todoService.findAllTodo();

  return res.status(200).json({ data: todos });
});

router.get('/api/todos/:id', async (req, res, next) => {
  const todo = await todoService.findTodoById(req, res);

  if (!todo) return res.status(404).json({ message: 'todo not found' });

  return res.status(200).json({ data: todo });
});

router.post('/api/todos', async (req, res, next) => {
  const todo = await todoService.createNewTodo(req, res);

  return res.status(201).json({ data: todo });
});

router.put('/api/todos/:id', async (req, res, next) => {
  const todo = await todoService.findTodoById(req, res);

  if (!todo) return res.status(404).json({ message: 'todo not found' });
  await todoService.updateTodo(req, res);

  return res.status(200).json({ message: 'Todos updated successfulll' });
});

router.delete('/api/todos/:id', async (req, res, next) => {
  const todo = await todoService.findTodoById(req, res);

  if (!todo) return res.status(404).send;
  await todoService.deleteTodo(req, res);

  return res.status(200).json({ message: 'Todos deleted successfulll' });
});

module.exports = router;
