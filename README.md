# hmac-express

A simple middleware to be used with express. It checks if the HMAC digest of the body (c) is equal to the value of the one provided through the query string.

	npm install hmac-express

# Getting Started

This middleware requires three parameters when it is created. The first two are the algorithm and the secret key that will be used by the createHmac function of the crypto library. The third one is the name of the query parameter containing the HMAC digest to check.

``` javascript
var middleware = require("hmac-express")("sha-256", "secret", "token")

app.get("/", middleware, function(request, response) {
	response.send("Hello")
})

```

By default the encoding of the digest is in hex but it can be changed by passing a fourth parameter. This parameter is a JSON object and the key to change the encoding is "encoding" (This value should be one of the value accepted by the method hmac.digest of the crypto library).

``` javascript
var opts = {
	encoding = "base64"
}
var middleware = require("hmac-express")("sha-256", "secret", "token", opts)

```

# License
Copyright (c) 2016 Gautier TANGUY

MIT License