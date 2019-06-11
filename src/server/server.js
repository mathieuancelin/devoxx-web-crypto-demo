const fs = require('fs');
const https = require('https');

const _ = require('lodash');
const express = require('express');
const bodyParser = require('body-parser');

const { bcrypt, rsa, aes } = require('./crypto');

const options = {
  key: fs.readFileSync("./certs/cert.key"),
  cert: fs.readFileSync("./certs/cert.cer"),
  ca: fs.readFileSync("./certs/ca.cer"),
};

class Server {
  
  constructor(read) {
    this.users = {};
    this.messages = {};
    this.writeState = this.writeState.bind(this);
    if (read) {
      try {
        const rawState = fs.readFileSync('./state.json', 'utf8');
        const state = JSON.parse(rawState);
        this.users = state.users;
        this.messages = state.messages;
        console.log('State loaded !');
      } catch(e) {
        console.log('No state file yet');
      }
    }
    if (Object.keys(this.users).length === 0) {
      console.log('Creating users for the demo !');
      this.createUser('bob@foo.bar', 'password', 'Bobby Boby');
      this.createUser('alice@foo.bar', 'password', 'Ally Alice');
    }    
    this.interval = setInterval(this.writeState, 2000);
  }

  stop() {
    clearInterval(this.interval);
  }

  writeState() {
    fs.writeFileSync('./state.json', JSON.stringify({
      users: this.users,
      messages: this.messages
    }, null, 2));
  }

  createUser(email, password, name) {
    const hash = bcrypt.hashSync(password, 10);
    this.users[email] = {
      email,
      name,
      password: hash
    };
  }

  login(email, password) {
    const user = this.users[email];
    if (user) {
      if (bcrypt.compareSync(password, user.password)) {
        return user;
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  storeKey(email, salt, publicKey, privateKey) {
    const user = this.users[email];
    user.salt = salt;
    user.publicKey = publicKey;
    user.privateKey = privateKey;
    this.users[email] = user;
  }

  sendMessage(email, message, sem) {
    const messagesTo = this.messages[message.to] || [];
    messagesTo.push(message);
    this.messages[message.to] = messagesTo;
    if (sem) {
      const messagesFrom = this.messages[email] || [];
      messagesFrom.push(sem);
      this.messages[email] = messagesFrom;
    }
  }

  loadMessages(email) {
    const messages = this.messages[email] || [];
    return messages;
  }

  getPublicKey(email) {
    const user = this.users[email];
    if (user) {
      if (user.publicKey) {
        return user.publicKey;
      }
    }
    return null;
  }

  state() {
    return {
      users: this.users,
      messages: this.messages
    };
  }
}

const app = express();
const port = process.env.PORT || 8080;
const httpsPort = process.env.HTTPS_PORT || 8443;
let server = new Server(true);

app.use(bodyParser.json());

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
  next();
});

app.use(express.static('dist'));
app.use('/openpgp', express.static('openpgp'));

app.get('/api/state', (req, res) => {
  res.send(server.state());
});

app.delete('/api/state', (req, res) => {
  server.stop();
  server = new Server(false);
  res.send({ done: true });
});

app.get('/api/users', (req, res) => {
  res.send(Object.keys(server.users).map(k => server.users[k]).map(u => ({ email: u.email, name: u.name, publicKey: u.publicKey })));
});

app.post('/api/users', (req, res) => {
  const { name, email, password } = req.body;
  server.createUser(email, password, name);
  res.status(201).send({ name, email, password });
});

app.post('/api/users/_login', (req, res) => {
  const user = server.login(req.body.email, req.body.password);
  if (user) {
    res.type('json').status(200).send(user);
  } else {
    res.type('json').status(500).send({ error: 'bad login' });
  }
});

app.post('/api/users/:email/key', (req, res) => {
  const email = req.params.email;
  server.storeKey(email, req.body.salt, req.body.publicKey, req.body.privateKey);
  res.send({ done: true });
});

app.post('/api/users/:email/messages', (req, res) => {
  const email = req.params.email;
  server.sendMessage(email, req.body.message, req.body.sem);
  res.send({ done: true });
});

app.get('/api/users/:email/messages', (req, res) => {
  const email = req.params.email;
  const messages = server.loadMessages(email);
  res.send(messages);
});

app.get('/api/users/:email/key', (req, res) => {
  const email = req.params.email;
  const publicKey = server.getPublicKey(email);
  res.send({ publicKey });
});

app.options('/*', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
  res.send('');
});

app.use((err, req, res, next) => {
  if (err) {
    console.log(err);
    res.status(500).send({ error: err.message })
  } else {
    try {
      res.set('Access-Control-Allow-Origin', '*');
      res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
      res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
      next();
    } catch(e) {
      res.status(500).send({ error: e.message })
    }
  }
});

app.listen(port, () => {
  console.log(`web-crypto-demo listening on port ${port}!`);
});

https.createServer(options, app).listen(httpsPort, (e, a) => {
  console.log(`web-crypto-demo listening on port ${httpsPort}!`);
});
