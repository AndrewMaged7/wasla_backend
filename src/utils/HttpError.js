// an error with an HTTP status code, e.g. throw new HttpError(404, 'User not found')
class HttpError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

module.exports = HttpError;