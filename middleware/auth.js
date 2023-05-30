const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication failed: Token not provided' });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Authentication failed: Invalid token' });
    }

    // The token is valid, store the decoded information in the
    // req.user = decoded;
    next();
  });
};

module.exports = authenticateToken;
