const cryptoJS = require('crypto-js');
const helpers = {}

function onlyUnique(value, index, self) {
    return self.indexOf(value) === index;
}

helpers.getAnchorHREFUrlList = function (input) {
    var re = /href=\s*"(.*?)"/g
    var m;
    var result = [];
    do {
        m = re.exec(input);
        if (m) {
            result.push(m[1]);
        }
    } while (m);
    return result.filter(onlyUnique);
}

helpers.getRandomKey = function (iters) {
    key = "";
    for (var i = 0; i < iters; i++) key += Math.random().toString(36).substring(2, 15);
    return key;
}

helpers.replaceAnchorHREF = function (body, url1, url2) {
    var re = new RegExp("/href=\s*\"(" + url1 + ")\"/g");
    body.replace(re, function (a, b) {
        return 'href="' + url2 + '"';
    });
};

helpers.decode = function (encPayload) {
    var payloadStr;
    try {
        var parsedWordArray = cryptoJS.enc.Base64.parse(encPayload);
        payloadStr = parsedWordArray.toString(cryptoJS.enc.Utf8);
    } catch (error) {
        payloadStr  = false;
    }
    return payloadStr;
}

helpers.encode = function (payload) {

    var payload_str = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
    var wordArray = cryptoJS.enc.Utf8.parse(payload_str)
    return cryptoJS.enc.Base64.stringify(wordArray);
    
}

helpers.encodeBase64AndSign = function (payload, signingKey) {

    var payload_str = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
    var wordArray = cryptoJS.enc.Utf8.parse(payload_str)
    var base64 = cryptoJS.enc.Base64.stringify(wordArray);
    var signature = cryptoJS.HmacSHA256(base64, signingKey);
    signature = signature.toString(cryptoJS.enc.base64);
    return { 'encoded_payload': base64, 'signature': signature };
}

helpers.verifyPayload = function (encodedPayload, signature, signing_key) {
    if (encodedPayload && signature) {
        try {
            var parsedWordArray = cryptoJS.enc.Base64.parse(encodedPayload);
            var payloadStr = parsedWordArray.toString(cryptoJS.enc.Utf8);
            try {
                var payload = JSON.parse(payloadStr);
            } catch (error) {
                payload = payloadStr;
            }
            var result = this.encodeBase64AndSign(payload, signing_key);
            if (result.signature === signature) {
                return payload;
            } else {
                return false;
            }
        } catch (error) {
            return false;
        }

    } else {
        return false;
    }
}

module.exports = helpers;