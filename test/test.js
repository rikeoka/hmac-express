var crypto = require("crypto")
var hmacExpress = require("../index")

describe("hmac-express", function() {

	it("should pass with an empty JSON body", function(done) {
		var middleware = hmacExpress("sha256", "secret", "token")
		var hmac = crypto.createHmac("sha256", "secret")
		var body = {}
		hmac.update(JSON.stringify(body))

		var request = {
			"body": body,
			"query": {
				"token": hmac.digest("hex")
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})

	it("should pass with a JSON body", function(done) {
		var middleware = hmacExpress("sha256", "secret", "token")
		var hmac = crypto.createHmac("sha256", "secret")
		var body = {
			"key1": "value1",
			"Key2": {
				"key21": "value21",
				"key22": "value22",
			}
		}
		hmac.update(JSON.stringify(body))

		var request = {
			"body": body,
			"query": {
				"token": hmac.digest("hex")
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})

	it("should not pass if the hmac of the received body is different", function(done) {
		var middleware = hmacExpress("sha256", "secret", "token")
		var body = {
			"key1": "value1",
			"Key2": {
				"key21": "value21",
				"key22": "value22",
			}
		}

		var request = {
			"body": body,
			"query": {
				"token": "wronghmac"
			}
		}

		var response = {
			sendStatus: function(code) {
				return done()
			}
		}
		return middleware(request, response, function() {
			return done(new Error("It should not have passed"))
		})
	})

	it("should pass with the header version and a different encoding", function(done) {
		var opts = {
			encoding: "base64",
    		header: "timestamp"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)
		var hmac = crypto.createHmac("sha256", "secret")

		hmac.update("12345T")

		var request = {
			"query": {
				"token": hmac.digest("base64")
			},
			"headers": {
				"timestamp": "12345T"
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})

	it("should not pass if the hmac of the received header is different", function(done) {
		var opts = {
    		header: "timestamp"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)

		var request = {
			"query": {
				"token": "wronghmac"
			},
			"headers": {
				"timestamp": "12345T"
			}
		}

		var response = {
			sendStatus: function(code) {
				return done()
			}
		}
		return middleware(request, response, function() {
			return done(new Error("It should not have passed"))
		})
	})

})
