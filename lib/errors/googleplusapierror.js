/**
 *
 *
 * @constructor
 * @param {string} [message]
 * @param {number} [code]
 * @access public
 */
function MolchAPIError(message, code) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'MolchAPIError';
  this.message = message;
  this.code = code;
}

// Inherit from `Error`.
MolchAPIError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = MolchAPIError;
