import 'babel-polyfill';

import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import moment from 'moment';
import _ from 'lodash';

// import { aes, rsa, bcrypt, generateRandomKey } from './no-crypto';
// import { aes, rsa, bcrypt, generateRandomKey } from './crypto-openpgp';
// import { aes, rsa, bcrypt, generateRandomKey } from './crypto-lib';
// import { aes, rsa, bcrypt, generateRandomKey } from './crypto';

import * as CryptoModuleNoCrypto from './no-crypto';
import * as CryptoModuleOpenPgpCrypto from './crypto-openpgp';
import * as CryptoModuleLibCrypto from './crypto-lib';
import * as CryptoModuleCrypto from './crypto';

const modules = {
  'no-crypto': CryptoModuleNoCrypto,
  'crypto-lib': CryptoModuleLibCrypto,
  'crypto-openpgp': CryptoModuleOpenPgpCrypto,
  'crypto': CryptoModuleCrypto,
}

function parseQuery() {
  const query = window.location.search.replace('?', '');
  const values = {};
  if (query.trim() !== '') {
    query.split('&').map(tuple => {
      const parts = tuple.split('=');
      values[parts[0]] = parts[1];
    });
  }
  return values;
}

class Client {

  constructor(module) {
    const mod = modules[module] || CryptoModuleCrypto;
    this.aes = mod.aes;
    this.rsa = mod.rsa;
    this.bcrypt = mod.bcrypt;
    this.generateRandomKey = mod.generateRandomKey;
  }

  server = {
    clearState() {
      return fetch(`/api/state`, {
        method: 'DELETE',
        headers: {
          'Accept': 'application/json'
        },
      }).then(r => r.json());
    },
    state() {
      return fetch(`/api/state`).then(r => r.json());
    },
    users() {
      return fetch(`/api/users`).then(r => r.json());
    },
    loadMessages(email) {
      return fetch(`/api/users/${email}/messages`).then(r => r.json());
    },
    login(email, password) {
      return fetch(`/api/users/_login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email, password
        })
      }).then(r => r.json());
    },
    storeKey(email, salt, publicKey, privateKey) {
      return fetch(`/api/users/${email}/key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email, salt, publicKey, privateKey
        })
      }).then(r => r.json());
    },
    getPublicKey(email) {
      return fetch(`/api/users/${email}/key`).then(r => r.json());
    },
    sendMessage(email, message, sem) {
      return fetch(`/api/users/${email}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email, message, sem
        })
      }).then(r => r.json());
    },
    createUser(email, name, password) {
      return fetch(`/api/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email, name, password
        })
      }).then(r => r.json());
    }
  }

  users() {
    return this.server.users();
  }

  clearState() {
    return this.server.clearState();
  }

  state() {
    return this.server.state();
  }

  generateSalt() {
    return this.bcrypt.genSaltSync(10);
  }

  encryptPrivateKey(privateKey, salt, password) {
    const hash = this.bcrypt.hashSync(password, salt);
    return this.aes.encrypt(JSON.stringify(privateKey), hash);
  }

  decryptPrivateKey(encodedPrivateKey, salt, password) {
    const hash = this.bcrypt.hashSync(password, salt);
    return this.aes.decrypt(encodedPrivateKey, hash).then(pk => JSON.parse(pk));
  }

  loadMessage() {
    return this.server.loadMessages(this.email).then(_messages => {
      const messages = _messages || [];
      return Promise.all(messages.map(message => {
        return this.decryptMessage(message).then(decryptedMessage => [message, decryptedMessage]);
      })).then(messages => {
        const decryptedMessages = messages.map(arr => {
          const [message, decryptedMessage] = arr;
          return { ...message, content: decryptedMessage };
        });
        this.messages = decryptedMessages;
        return decryptedMessages;
      });  
    });
  }

  login(email, password) {
    return this.server.login(email, password).then(res => {
      if (res) {
        this.email = email;
        this.password = password;
        this.name = res.name
        if (!res.privateKey && !res.publicKey) {
          console.log('Generating keys ...');
          return this.rsa.genKeyPair(2048, name, email).then(pair => {
            this.privateKey = pair.privateKey;
            this.publicKey = pair.publicKey;
            this.salt = this.generateSalt();
            console.log('Sending keys to server');
            return this.aes.encrypt(this.salt, this.password).then(encryptedSalt => {
              return this.encryptPrivateKey(this.privateKey, this.salt, this.password).then(encryptedPrivateKey => {
                return this.server.storeKey(
                  this.email,
                  encryptedSalt,
                  this.publicKey,
                  encryptedPrivateKey
                ).then(() => {
                  console.log('Logged in as ' + this.email);
                  return this.loadMessage();
                });
              });
            });
          });
        } else {
          console.log('login', res.salt, this.password)
          return this.aes.decrypt(res.salt, this.password).then(salt => {
            return this.decryptPrivateKey(res.privateKey, salt, this.password).then(decryptedPrivateKey => {
              this.salt = salt;
              this.privateKey = decryptedPrivateKey;
              this.publicKey = res.publicKey;
              console.log('Logged in as ' + this.email);
              return this.loadMessage();
            });
          });
        }
      } else {
        console.log('Bad login ...');
        return null;
      }
    });
  }

  encryptMessage(content, pubKey) {
    const messageKey = this.generateRandomKey();
    return this.aes.encrypt(content, messageKey).then(encryptedContent => {
      return this.rsa.encrypt(messageKey, pubKey || this.publicKey).then(encryptedKey => {
        return {
          key: encryptedKey,
          content: encryptedContent
        };
      });
    });
  }

  decryptMessage(message) {
    return this.rsa.decrypt(message.key, this.privateKey).then(key => {
      return this.aes.decrypt(message.content, key);
    });
  }

  sendMessage(to, content) {
    return this.server.getPublicKey(to).then(res => {
      const toPublicKey = res.publicKey;
      if (toPublicKey) {
        return this.encryptMessage(content, toPublicKey).then(encryptedMessage => {
          encryptedMessage.from = this.email;
          encryptedMessage.to = to;
          encryptedMessage.at = Date.now();
          encryptedMessage.id = this.generateRandomKey();
          if (to === this.email) {
            return this.server.sendMessage(this.email, encryptedMessage);
          } else {
            return this.encryptMessage(content).then(selfEncryptedMessage => {
              selfEncryptedMessage.from = this.email;
              selfEncryptedMessage.to = to;
              selfEncryptedMessage.at = encryptedMessage.at;
              selfEncryptedMessage.id = encryptedMessage.id;
              return this.server.sendMessage(this.email, encryptedMessage, selfEncryptedMessage);
            });
          }
        });
      } else {
        console.log('No public key for user', to);
        return null;
      }
    });
  }
}

class App extends Component {

  state = {
    username: 'bob@foo.bar',
    password: 'password',
    email: null,
    privateKey: null,
    publicKey: null,
    salt: null,
    messages: [],
    error: null,
    contacts: [],
    to: '--',
    content: '',
    state: {},
    form: {},
    moduleName: '--'
  };

  componentDidMount() {
    const moduleName = parseQuery().module || 'crypto';
    this.client = new Client(moduleName);
    this.reload();
    this.interval = setInterval(() => this.reload(), 2000);
    this.setState({ moduleName })
  }

  componentWillUnmount() {
    if (this.interval) clearInterval(this.interval);
  }

  doLogin = () => {
    this.client.login(this.state.username, this.state.password).then(res => {
      if (!res) {
        this.setState({ error: 'Bad login ...' });
      } else {
        this.setState({
          name: this.client.name,
          email: this.client.email,
          privateKey: this.client.privateKey,
          publicKey: this.client.publicKey,
          salt: this.client.salt,
          messages: this.client.messages
        });
      }
    });
  }

  send = () => {
    this.client.sendMessage(this.state.to, this.state.content).then(r => {
      this.setState({ to: '--', content: '' });
      this.reload();
    });
  }

  reload = () => {
    this.client.loadMessage(this.state.email).then(r => {
      this.setState({ messages: this.client.messages });
    });
    this.client.users().then(contacts => this.setState({ contacts }));
    this.client.state().then(state => this.setState({ state }));
  }

  createAccount = () => {
    if (this.state.form.password && (this.state.form.password === this.state.form.password2)) {
      this.client.server.createUser(this.state.form.email, this.state.form.name, this.state.form.password).then(res => {
        this.setState({ username: this.state.form.email, password: this.state.form.password, form: {}});
        $('#createAccountModal').modal('toggle');
      });
    } else {
      window.alert("Passwords don't match !!!");
    }
  }

  cleanupAndLoad = (e, path) => {
    e.preventDefault();
    this.client.clearState().then(e => window.location = path);
  }

  renderLogin = () => {
    return (
      <form className="form-signin">
        <h1 className="h3 mb-3 font-weight-normal">Please log in</h1>
        <label htmlFor="inputEmail" className="sr-only">Email address</label>
        <input type="email" id="inputEmail" className="form-control" placeholder="Email address" required="" onChange={e => this.setState({ username: e.target.value })} value={this.state.username} />
        <label htmlFor="inputPassword" className="sr-only">Password</label>
        <input type="password" id="inputPassword" className="form-control" placeholder="Password" required="" onChange={e => this.setState({ password: e.target.value })} value={this.state.password} />
        <button className="btn btn-lg btn-primary btn-block" type="button" onClick={this.doLogin}>Log in</button>
        <button className="btn btn-lg btn-success btn-block" type="button" data-toggle="modal" data-target="#createAccountModal">Create account</button>
        <div className="modal fade" id="createAccountModal" tabIndex="-1" role="dialog" aria-hidden="true">
          <div className="modal-dialog" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title" id="exampleModalLabel">Create account</h5>
                <button type="button" className="close" data-dismiss="modal" aria-label="Close">
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="modal-body">
              <div>
                <div className="form-group">
                  <label htmlFor="email">Email address</label>
                  <input onChange={e => this.setState({ form: { ...this.state.form, email: e.target.value } })} type="email" className="form-control" id="email" aria-describedby="emailHelp" placeholder="Enter email" />
                </div>
                <div className="form-group">
                  <label htmlFor="name">Name</label>
                  <input onChange={e => this.setState({ form: { ...this.state.form, name: e.target.value } })} type="email" className="form-control" id="name" aria-describedby="nameHelp" placeholder="Enter your name" />
                </div>
                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <input onChange={e => this.setState({ form: { ...this.state.form, password: e.target.value } })} type="password" className="form-control" id="password" placeholder="Password" />
                </div>
                <div className="form-group">
                  <label htmlFor="password2">Re-type password</label>
                  <input onChange={e => this.setState({ form: { ...this.state.form, password2: e.target.value } })} type="password" className="form-control" id="password2" placeholder="Password" />
                </div>
              </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" data-dismiss="modal">Close</button>
                <button type="button" className="btn btn-primary" onClick={this.createAccount}>Create account</button>
              </div>
            </div>
          </div>
        </div>
        {this.state.error && <div className="alert alert-danger" role="alert">{this.state.error}</div>}
        <div style={{ display: 'none', flexDirection: 'column', marginTop: 40 }}>
          <button type="button" style={{ marginBottom: 2 }} className="btn btn-outline-secondary btn-xs" onClick={e => this.cleanupAndLoad(e, "/?module=no-crypto")}>use no crypto</button>
          <button type="button" style={{ marginBottom: 2 }} className="btn btn-outline-secondary btn-xs" onClick={e => this.cleanupAndLoad(e, "/?module=crypto")}>use window.crypto</button>
          <button type="button" style={{ marginBottom: 2 }} className="btn btn-outline-secondary btn-xs" onClick={e => this.cleanupAndLoad(e, "/?module=crypto-lib")}>use jsencrypt</button>
          <button type="button" style={{ marginBottom: 2 }} className="btn btn-outline-secondary btn-xs" onClick={e => this.cleanupAndLoad(e, "/?module=crypto-openpgp")}>use openpgp.js</button>
        </div>
      </form>
    );
  }

  renderMessages = () => {
    return _.reverse(_.sortBy(this.state.messages, m => m.at)).map(message => {
      return (
        <div key={message.id || message.at} className="card mb-4 shadow-sm">
          <div className="card-body">
            <p className="card-text" style={{ fontWeight: 'bold' }}>{message.from} - {message.to}</p>
            <p className="card-text">{message.content}</p>
            <div className="d-flex justify-content-end align-items-center" style={{ width: '100%' }}>
              <small className="text-muted">{moment(message.at).format('DD/MM/YYYY HH:mm:ss')}</small>
            </div>
          </div>
        </div>
      );
    });
  }

  renderApp() {
    if (this.state.email) {
      return (
        <div>
          <header>
            <div className="navbar navbar-dark bg-dark shadow-sm">
              <div className="container d-flex justify-content-between">
                <a href="/" className="navbar-brand d-flex align-items-center">
                  <i className="fas fa-comments" />
                  <strong>Messages</strong>
                </a>
                <p  onClick={e => window.location.reload()} style={{ color: 'white', marginTop: 16, cursor: 'pointer' }}>
                  {this.state.name} ({this.state.email})  <i className="fas fa-sign-out-alt" /> 
                </p>
              </div>
            </div>
          </header>
          <main role="main">
            <section className="jumbotron text-center" style={{ paddingBottom: 0 }}>
              <div className="container">
                <h2 className="jumbotron-heading">Send message</h2>
                <select className="form-control" onChange={e => this.setState({ to: e.target.value})} value={this.state.to}>
                  {[<option key="--" value="--"></option>].concat(this.state.contacts.map(c => <option key={c.email} value={c.email}>{c.name}</option>))}
                </select>
                <textarea style={{ marginTop: 5 }} className="form-control" value={this.state.content} onChange={e => this.setState({ content: e.target.value})} rows="3"></textarea>
                <p>
                  <button type="button" onClick={this.send} className="btn btn-primary my-2"><i className="fas fa-paper-plane" /> Send</button>
                  <button type="button" onClick={this.reload} className="btn btn-success my-2" style={{ marginLeft: 5 }}><i className="fas fa-sync-alt" /> Reload messages</button>
                </p>
              </div>
            </section>
            <div className="album py-5 bg-light">
              <div className="container" style={{ display: 'flex', flexDirection: 'column' }}>
                {this.renderMessages()}
              </div>
            </div>
          </main>
        </div>
      );
    }
    return this.renderLogin();
  }

  render() {
    return (
      <div>
        {this.renderApp()}
        <div style={{ display: 'flex', position: 'fixed', height: 45, right: 0, bottom: 0, justifyContent: 'center', alignItems: 'space-around' }}>
          <p style={{ display: 'none', marginRight: 5, marginTop: 10 }}>
            {this.state.moduleName}
          </p>
          <div className="btn-group dropup">
            <button type="button" style={{ width: 136, height: 35, marginTop: 5, marginRight: 5 }} className="btn btn-secondary btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {this.state.moduleName}
            </button>
            <div className="dropdown-menu">
              <a href="#" style={{ marginBottom: 2 }} className="dropdown-item" onClick={e => this.cleanupAndLoad(e, "/?module=no-crypto")}>use no crypto</a>
              <a href="#" style={{ marginBottom: 2 }} className="dropdown-item" onClick={e => this.cleanupAndLoad(e, "/?module=crypto")}>use window.crypto</a>
              <a href="#" style={{ marginBottom: 2 }} className="dropdown-item" onClick={e => this.cleanupAndLoad(e, "/?module=crypto-lib")}>use jsencrypt</a>
              <a href="#" style={{ marginBottom: 2 }} className="dropdown-item" onClick={e => this.cleanupAndLoad(e, "/?module=crypto-openpgp")}>use openpgp.js</a>
            </div>
          </div>
          <button 
            type="button" className="btn btn-primary btn-sm" data-toggle="modal" data-target="#state-modal" 
            style={{ margin: 5 }}>server state</button>
          <button 
            onClick={e => this.client.clearState().then(e => window.location.reload())} 
            type="button" className="btn btn-danger btn-sm" style={{ margin: 5 }}>clear server state</button>
        </div>
        <div className="modal" id="state-modal" tabIndex="-1" role="dialog">
            <div className="modal-dialog modal-lg" role="document">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">Server state</h5>
                  <button type="button" className="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                  </button>
                </div>
                <div className="modal-body">
                  <pre>{JSON.stringify(this.state.state, null, 2)}</pre>
                </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
              </div>
            </div>
          </div>
      </div>
    )
  }
}

ReactDOM.render(<App />, document.getElementById('app'));


/**
 
aes.encrypt('hello', 'secret').then(enc => {
  console.log('enc', enc);
  aes.decrypt(enc, 'secret').then(dec => {
    console.log('dec', dec);
  });
});

rsa.genKeyPair(4096, 'bobby', 'bobby@foo.bar').then(pair => {
  return rsa.encrypt('hello', pair.publicKey).then(enc => {
    return rsa.decrypt(enc, pair.privateKey).then(dec => {
      return console.log('dec', dec);
    });
  });
});

**/
