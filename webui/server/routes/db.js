const express = require('express');
const router = express.Router();

const restify = require('express-restify-mongoose')

const Subscriber = require('../models/subscriber');

// Do not return the full subscriber collection (large DBs freeze the WebUI).
// Clients must use GET /Subscriber/:imsi for a single record.
router.get('/Subscriber', (req, res, next) => {
  if (Object.keys(req.query).length === 0) {
    return res.json([]);
  }
  next();
});

restify.serve(router, Subscriber, {
  prefix: '',
  version: '',
  idProperty: 'imsi'
});

const Profile = require('../models/profile');
restify.serve(router, Profile, {
  prefix: '',
  version: ''
});

const Account = require('../models/account');
restify.serve(router, Account, {
  prefix: '',
  version: '',
  idProperty: 'username'
});

module.exports = router;