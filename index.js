var crypto = require("crypto")

module.exports = function (algorithm, key, token, opts) {
	var algorithm = algorithm
	var key = key
	var token = token
	var encoding =  "hex"
	if (opts) {
		encoding = opts.encoding || "hex"
	}

	return function(request, response, next) {
		var hmac = crypto.createHmac(algorithm, token)
		if (request.body)
			hmac.update(JSON.stringify(request.body))

		if (!request.query[token] || request.query[token] != hmac.digest(encoding)) return response.sendStatus(401)

		next()
	}
}
