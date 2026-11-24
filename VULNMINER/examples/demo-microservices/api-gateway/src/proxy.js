// Ejemplos intencionalmente vulnerables para demo académica local.
async function proxy(req, res) {
  const response = await fetch(req.query.target);
  const data = await response.json();
  res.send(data);
}

function updateUser(user, req) {
  Object.assign(user, req.body);
  return user.save();
}

module.exports = { proxy, updateUser };
