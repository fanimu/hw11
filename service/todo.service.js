const todoRepository = require('../repository/todo.repository');

const findAllTodo = async () => {
  return await todoRepository.findAll();
};

const findTodoById = async (req, res) => {
  const todo = await todoRepository.findById(req.params.id);

  return todo;
};

const createNewTodo = async (req, res) => {
  return await todoRepository.save(req.fields);
};

const updateTodo = async (req, res) => {
  const todo = await todoRepository.findById(req.params.id);

  return await todoRepository.updateById(req.params.id, req.fields);
};

const deleteTodo = async (req, res) => {
  const todo = await todoRepository.findById(req.params.id);

  return await todoRepository.deleteById(req.params.id);
};

module.exports = {
  findAllTodo,
  findTodoById,
  createNewTodo,
  updateTodo,
  deleteTodo,
};
