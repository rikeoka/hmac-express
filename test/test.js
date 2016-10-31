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

	it("should pass with an empty JSON body with header token", function(done) {
		var opts = {
			header: "HMAC"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)
		var hmac = crypto.createHmac("sha256", "secret")
		var body = {}

		hmac.update(JSON.stringify(body))

		var request = {
			"body": body,
			"headers": {
				"HMAC": hmac.digest("hex")
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})

	it("should pass with a JSON body with header token", function(done) {
		var opts = {
			header: "HMAC"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)
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
			"headers": {
				"HMAC": hmac.digest("hex")
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})

	it("should not pass if the hmac of the received body is different with header token", function(done) {
		var opts = {
			header: "HMAC"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)
		var body = {
			"key1": "value1",
			"Key2": {
				"key21": "value21",
				"key22": "value22",
			}
		}

		var request = {
			"body": body,
			"headers": {
				"HMAC": "wronghmac"
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
				header: "HMAC"
		}
		var middleware = hmacExpress("sha256", "secret", "token", opts)
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
			"headers": {
				"HMAC": hmac.digest("base64")
			}
		}

		var response = {
			sendStatus: function(code) {
				return done(new Error("Fail with the wrong error code"))
			}
		}
		return middleware(request, response, done)
	})
})
