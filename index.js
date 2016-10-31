var crypto = require("crypto")
var bufferEq = require("buffer-equal-constant-time")

module.exports = function (algorithm, key, token, opts) {
	var algorithm = algorithm
	var key = key
	var token = token
	var encoding =  "hex"
	var header
	var raw = false
	if (opts) {
		encoding = opts.encoding || "hex"
		header = opts.header
		raw = opts.raw
	}

	return function(request, response, next) {
		var hmac = crypto.createHmac(algorithm, key)
		if (request.body && !raw) {
			hmac.update(JSON.stringify(request.body))
		} else if (request.body && raw === true) {
			hmac.update(request.body)
		}

		if (!(header && request.headers[header]) && !request.query[token]) return response.sendStatus(401)

		var receivedHmac = crypto.createHmac(algorithm, key)
		if (header && request.headers[header]) {
			receivedHmac.update(request.headers[header])
		} else {
			receivedHmac.update(request.query[token])
		}
		var computedHmac = crypto.createHmac(algorithm, key)
		computedHmac.update(hmac.digest(encoding))

		if (bufferEq(new Buffer(receivedHmac.digest(encoding)), new Buffer(computedHmac.digest(encoding)))) {
			next()
		} else {
			return response.sendStatus(401)
		}
	}
}
