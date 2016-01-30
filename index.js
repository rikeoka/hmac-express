var crypto = require("crypto")

exports.middleware = function (algorithm, key, token) {
	var algorithm = algorithm
	var key = key
	var token = token

	return function(request, response, next) {
		var hmac = crypto.createHmac(algorithm, token)
		if (request.body)
			hmac.update(JSON.stringify(request.body))

		if (!request.query[token] || request.query[token] != hmac.digest("hex")) return response.sendStatus(401)

		next()
	}
}
