/**
 * Command Execution Utility
 * Wraps child_process.exec with Promise support
 */

const { exec } = require('child_process');

function execCmd(cmd, timeout = 5000) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout }, (err, stdout, stderr) => {
      if (err) {
        return reject(new Error(stderr || err.message));
      }
      resolve(stdout.trim());
    });
  });
}

module.exports = {
  execCmd,
};
