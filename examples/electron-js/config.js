const packageJson = require('./package.json');

module.exports = {
  app_name: packageJson.name,
  version: packageJson.version,
  channel: "nightly",
  owner: "ku9n",
};