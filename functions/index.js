const functions = require('firebase-functions');
const axios = require('axios');
const helpers = require('./helpers');
const express = require('express');

//const bodyParser = require('body-parser'); //firebase uses its own body parser before the express applications gets executed
const app = express();
const msgApp = express();
const clickApp = express();

const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);

//app.use(bodyParser.json()); //firebase uses its own body parser before the express applications gets executed :()

// random strings
const getRandomKey = function () {
    return helpers.getRandomKey(5);
}

const getKeys = function (fbSnapshotValue) {
    keys = []
    for (var k in fbSnapshotValue) keys.push(k)
    return keys;
}

var CONFIG = {};
admin.database().ref("config").once("value", (snap) => {
    CONFIG = snap.val();
});

//middleware: this api only accepts content-type = application/json

const verifyContentType = function (req, res, next) {
    if (['POST', 'PUT'].indexOf(req.method) !== -1) {
        if (req.is('application/json')) {
            next();
        } else {
            res.status(400).send({ "error": "content-type should be application/json" });
            res.end();
        }
    } else {
        next();
    }
};

app.use(verifyContentType);

app.post("/domain/:domain/dodnscheck", (req, res) => {
    domain = req.params.domain;
    admin.database().ref("/domain")
        .orderByChild("domain")
        .equalTo(domain)
        .once("value", (snap) => {
            if (snap.val()) {
                var key = getKeys(snap.val())[0];
                var uri = CONFIG.baseURL + "analytics/dnscheck?key=" + snap.val()[key].validation_key
                axios.get(uri)
                    .then((response) => {
                        if (response.status == 200) {
                            res.send({ "message": "domain dns validated successfully" });
                        } else {
                            res.status(400).send({ "error": "response not ok" })
                        }
                    })
                    .catch((error) => {
                        res.status(400).send({ "error": "domain dns settings are incorrect" })
                    });
            } else {
                res.status(404).send({ "error": "domain not found" });
            }
        })

});

app.get("/dnscheck", (req, res) => {
    const validation_key = typeof req.query.key === 'string' ? req.query.key : false;
    if (validation_key) {
        domain = req.get('host');
        admin.database().ref('/domain')
            .orderByChild("domain")
            .equalTo(domain)
            .once("value", (snap) => {
                if (snap.val()) {
                    //domain exist
                    var key = getKeys(snap.val())[0];
                    doc = snap.val()[key];
                    if (validation_key === doc.validation_key) {
                        admin.database().ref("/domain/" + key).update({ "tracking_settings/dns_verified": true })
                            .then(() => {
                                res.send({ "message": "domain dns validated" });
                            })
                            .catch((error) => {
                                console.log(error);
                                res.status(500).send({ "error": "could not update domain record" });

                            });
                    } else {
                        res.status(400).send({ "error": "not valid key" })
                    }

                } else {
                    //domain does not exists
                    res.status(404).send({ "error": "domain not found" });
                }
            });
    } else {
        res.status(400).send({ "error": "invalid required params" });
    }
});

//the express app must call res.send, res.redirect or res.end before ending
app.get('/domain/:domain', (req, res) => {
    const domainParam = req.params.domain;
    const domainRef = admin.database().ref('/domain');
    domainRef.orderByChild("domain").equalTo(domainParam)
        .once("value", (snapshot) => {
            if (snapshot.val()) {
                fbDoc = snapshot.val();
                var key = getKeys(fbDoc)[0];
                delete fbDoc[key].signing_key;
                delete fbDoc[key].validation_key;
                res.send({ "key": key, "value": fbDoc[key] });
            } else {
                res.status(404).send({ 'error': 'domain ' + domainParam + ' was not found!' });
            }
        }, (error) => {
            console.log(error);
            res.status(500).send({ 'error': 'Internal error reading database' });
        })
});

app.post('/domain', (req, res) => {
    const params = req.body;
    const domain = typeof params.domain === 'string' && params.domain.length > 0 ? params.domain : false;
    //const signing_key = typeof params.signing_key === 'string' && params.signing_key.length >= 36 ? params.signing_key : false;
    const signing_key = getRandomKey();
    const validation_key = getRandomKey();
    const tracking_settings = typeof params.tracking_settings === 'object' ? params.tracking_settings : {}
    const tracking_hostname = typeof tracking_settings.tracking_hostname === 'string' && tracking_settings.tracking_hostname.length > 0 ? tracking_settings.tracking_hostname : false;
    console.log(domain, signing_key, tracking_hostname, tracking_settings);
    if (domain && signing_key && tracking_hostname) {
        const ref = admin.database().ref('/domain');
        ref.orderByChild("domain").equalTo(params.domain)
            .once("value", (snapshot) => {
                if (snapshot.val()) {
                    res.status(400).send({ "error": "domain already exists, you could use PUT method to update it" });
                } else {
                    const click_tracking = typeof tracking_settings.click_tracking === 'boolean' ? tracking_settings.click_tracking : false;
                    const open_tracking = typeof tracking_settings.open_tracking === 'boolean' ? tracking_settings.open_tracking : false;
                    const unsubscribes = typeof tracking_settings.unsubscribes === 'boolean' ? tracking_settings.unsubscribes : false;
                    const doc = {
                        domain,
                        signing_key,
                        validation_key,
                        tracking_settings: {
                            click_tracking,
                            open_tracking,
                            unsubscribes,
                            tracking_hostname,
                            dns_verified: false
                        },
                        counters: {
                            opens: 0,
                            unique_opens: 0,
                            clicks: 0,
                            unique_clicks: 0,
                            unsubscribes: 0,
                            processed: 0
                        }
                    }
                    const fbDoc = admin.database().ref("/domain").push(doc);
                    delete doc.signing_key;
                    delete doc.validation_key;
                    res.send({ "key": fbDoc.key, "value": doc });
                }
            }, (error) => {
                console.log(error);
                res.status(500).send({ 'error': 'Internal error reading database' });
            })
    } else {
        res.status(400).send({ "error": "invalid required params" });
    }
});

app.put('/domain', (req, res) => {
    const params = req.body;
    const domain = params.domain && params.domain.length > 0 ? params.domain : false;
    const tracking_settings = typeof params.tracking_settings === 'object' ? params.tracking_settings : {}
    const tracking_hostname = typeof tracking_settings.tracking_hostname === 'string' && tracking_settings.tracking_hostname.length > 0 ? tracking_settings.tracking_hostname : false;
    if (domain) {
        const ref = admin.database().ref('/domain');
        ref.orderByChild("domain").equalTo(domain)
            .once("value", (snapshot) => {
                if (snapshot.val()) {
                    //update the domain
                    var key = getKeys(snapshot.val())[0];
                    const processed = snapshot.val()[key].counters.processed;
                    updates = {};
                    if (tracking_hostname) {
                        if (processed === 0) {
                            updates['tracking_settings/tracking_hostname'] = tracking_hostname;
                        } else {
                            res.status(400).send({ "error": "tracking_hostname cannot be changed (processed > 0)" });
                        }
                    }
                    if (typeof tracking_settings.click_tracking === 'boolean') {
                        updates['tracking_settings/click_tracking'] = tracking_settings.click_tracking;
                    }
                    if (typeof tracking_settings.open_tracking === 'boolean') {
                        updates['tracking_settings/open_tracking'] = tracking_settings.open_tracking;
                    }
                    if (typeof tracking_settings.unsubscribes === 'boolean') {
                        updates['tracking_settings/unsubscribes'] = tracking_settings.unsubscribes;
                    }
                    admin.database().ref('/domain/' + key).update(updates)
                        .then(() => {
                            res.send({ "message": "domain updated" });
                        })
                        .catch((error) => {
                            console.log(error);
                            res.status(400).send({ "error": "cannot update domain" });
                        })
                } else {
                    res.status(400).send({ "error": "domain was not found" });
                }
            }, (error) => {
                console.log(error);
                res.status(500).send({ 'error': 'Internal error reading database' });
            })
    } else {
        res.status(400).send({ "error": "invalid required params" });
    }
});

app.delete("/domain/:domain", (req, res) => {
    fbRef = admin.database().ref("/domain")
        .orderByChild("domain")
        .equalTo(req.params.domain)
        .once("value", (snapshot) => {
            const doc = snapshot.val();
            if (doc) {
                //domain exists get the key
                var key = getKeys(snapshot.val())[0];
                admin.database().ref("/domain/" + key).set(null, (error) => {
                    if (!error) {
                        res.send({ "message": "domain was sucessfully deleted" });
                    } else {
                        console.log(error);
                        res.status(500).send({ "error": "error trying to delete the domain" });
                    }
                });
            } else {
                //not found
                res.status(400).send({ "error": "domain not found" });
            }
        }, (error) => {
            console.log(error);
            res.status(500).send({ 'error': 'Internal error reading database' });
        });
});

app.all('*', (req, res) => {
    res.status(404).end();
});

// messages endpoint

msgApp.use(verifyContentType);

msgApp.post("/", (req, res) => {
    const body = req.body;
    const msg = {};

    msg.id = typeof body.id === 'string' && body.id.length > 0 ? body.id : false;
    msg.tracking_host = typeof body.tracking_host === 'string' && body.tracking_host.length > 0 ? body.tracking_host : false;
    msg.from = typeof body.from === 'string' && body.from.length > 0 ? body.from : false;
    msg.to = typeof body.to === 'string' && body.to.length > 0 ? body.to : false;
    msg.subject = typeof body.subject === 'string' ? body.subject : false;
    msg.tags = typeof body.tags === 'object' && body.tags.constructor === Array ? body.tags : [];
    msg.html_body = typeof body.html_body === 'string' ? body.html_body : false;

    if (msg.id && msg.tracking_host && msg.from && msg.to && msg.subject
        && msg.tags && msg.html_body) {
        //valid params 
        admin.database().ref("/domain")
            .orderByChild("domain")
            .equalTo(msg.tracking_host)
            .once("value", (snap) => {
                if (snap.val()) {
                    //host exists
                    const key = getKeys(snap.val());
                    //const signingKey = (snap.val()[key]).signing_key;
                    const tracking_host = (snap.val()[key]).domain;

                    var newMsg = admin.database().ref("/message").push();
                    newMsg.set(msg, (error) => {
                        if (!error) {
                            console.log("random k="+helpers.getRandomKey(1));
                            //data saved sucessfully
                            var openURLs = helpers.getAnchorHREFUrlList(msg.html_body)
                            var trackingURLs = [];
                            openURLs.forEach((url) => {
                                //var encodedAndSigned = helpers.encodeBase64AndSign(newMsg.key, signingKey);
                                trackingURLs.push(
                                    admin.database().ref("/url/c/").push({
                                        "message": newMsg.key,
                                        "target": url,
                                        "k": helpers.getRandomKey(1)
                                    })
                                );
                            });
                            trackingURLs.forEach((urlRef)=> {
                                var k = null;
                                urlRef.once("value", (snap)=> {
                                    k = snap.val().k;
                                })
                                
                                urlRef.update({
                                    "tracking" : CONFIG.baseURL + "c/" + helpers.encode(urlRef.key) +"?k=" +k
                                });
                            });
                            res.send({ "message_id": newMsg.key });
                        } else {
                            //data not saved
                            res.status(500).send({ "error": "unable to save message" });
                        }
                    });
                } else {
                    //host dont exists
                    res.status(400).send({ "error": "tracking host does not exists" });
                }
            }, (error) => {
                console.log(error);
                res.status(500).send({ "error": "internal error retrieving tracking host" });
            })
    } else {
        //invalid params
        res.status(400).send({ "error": "invalid required params" });
    }


});

// click endpoint
clickApp.get("/:url_id", (req,res) => {
    var url_id = helpers.decode(req.params.url_id);
    var k = req.query.k;

    if (url_id) {
        urlRef = admin.database().ref("/url/c/"+url_id)
        .once("value",(snap)=>{
            if (snap.val()) {
                //url found
                var url = snap.val();
                if (url.k === k) {
                    //valid request, redirect
                    res.redirect(snap.val().target);  //@@TODO complement redirect html body like mailgun example.
                } else {
                    //not valid request
                    res.status(400).end();
                }
            } else {
                //url not found

            }
        }, (error) => {
            console.log("error retrieving from /url/c/");
            res.status(500).send({"error" : "internal error retrieving url target"});
        })

    } else {
        //url_id not valid
        res.status(400).end();
    }

});

clickApp.all("*", (req, res) => {
    res.status(404).end();
});

const analytics = functions.https.onRequest(app);
const message = functions.https.onRequest(msgApp);
const c = functions.https.onRequest(clickApp);

module.exports = {
    analytics,
    message,
    c
}