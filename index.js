const PORT = 8081 || process.env.PORT;
const app = require('./app');
const dotenv = require('dotenv');
dotenv.config();

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
