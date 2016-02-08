var crypto = require("crypto")

module.exports = function (algorithm, key, token, opts) {
	var algorithm = algorithm
	var key = key
	var token = token
	var encoding =  "hex"
	var header
	if (opts) {
		encoding = opts.encoding || "hex"
		header = opts.header
	}

	return function(request, response, next) {
		var hmac = crypto.createHmac(algorithm, key)
		if (header && request.headers[header]) {
			hmac.update(request.headers[header])
		} else if (request.body) {
			hmac.update(JSON.stringify(request.body))
		}

		if (!request.query[token] || request.query[token] != hmac.digest(encoding)) return response.sendStatus(401)

		next()
	}
}
