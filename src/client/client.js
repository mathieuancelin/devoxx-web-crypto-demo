import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import moment from 'moment';
import _ from 'lodash';

import { aes, rsa, bcrypt, generateRandomKey } from './crypto';

class Client {

  server = {
    clearState() {
      return fetch(`http://127.0.0.1:8080/api/state`, {
        method: 'DELETE',
        headers: {
          'Accept': 'application/json'
        },
      }).then(r => r.json());
    },
    state() {
      return fetch(`http://127.0.0.1:8080/api/state`).then(r => r.json());
    },
    users() {
      return fetch(`http://127.0.0.1:8080/api/users`).then(r => r.json());
    },
    loadMessages(email) {
      return fetch(`http://127.0.0.1:8080/api/users/${email}/messages`).then(r => r.json());
    },
    login(email, password) {
      return fetch(`http://127.0.0.1:8080/api/users/_login`, {
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
      return fetch(`http://127.0.0.1:8080/api/users/${email}/key`, {
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
      return fetch(`http://127.0.0.1:8080/api/users/${email}/key`).then(r => r.json());
    },
    sendMessage(email, message, sem) {
      return fetch(`http://127.0.0.1:8080/api/users/${email}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email, message, sem
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
    return bcrypt.genSaltSync(10);
  }

  encryptPrivateKey(privateKey, salt, password) {
    const hash = bcrypt.hashSync(password, salt);
    return aes.encrypt(JSON.stringify(privateKey), hash);
  }

  decryptPrivateKey(encodedPrivateKey, salt, password) {
    const hash = bcrypt.hashSync(password, salt);
    return aes.decrypt(encodedPrivateKey, hash).then(pk => JSON.parse(pk));
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
          return rsa.genKeyPair().then(pair => {
            this.privateKey = pair.privateKey;
            this.publicKey = pair.publicKey;
            this.salt = this.generateSalt();
            console.log('Sending keys to server');
            return aes.encrypt(this.salt, this.password).then(encryptedSalt => {
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
          return aes.decrypt(res.salt, this.password).then(salt => {
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
    const messageKey = generateRandomKey();
    return aes.encrypt(content, messageKey).then(encryptedContent => {
      return rsa.encrypt(messageKey, pubKey || this.publicKey).then(encryptedKey => {
        return {
          key: encryptedKey,
          content: encryptedContent
        };
      });
    });
  }

  decryptMessage(message) {
    return rsa.decrypt(message.key, this.privateKey).then(key => {
      return aes.decrypt(message.content, key);
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
          encryptedMessage.id = generateRandomKey();
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

  client = new Client();

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
    state: {}
  };

  componentDidMount() {
    this.reload();
    this.interval = setInterval(() => this.reload(), 2000);
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

  renderLogin = () => {
    return (
      <form className="form-signin">
        <img className="mb-4" src="/docs/4.2/assets/brand/bootstrap-solid.svg" alt="" width="72" height="72" />
        <h1 className="h3 mb-3 font-weight-normal">Please log in</h1>
        <label htmlFor="inputEmail" className="sr-only">Email address</label>
        <input type="email" id="inputEmail" className="form-control" placeholder="Email address" required="" onChange={e => this.setState({ username: e.target.value })} value={this.state.username} />
        <label htmlFor="inputPassword" className="sr-only">Password</label>
        <input type="password" id="inputPassword" className="form-control" placeholder="Password" required="" onChange={e => this.setState({ password: e.target.value })} value={this.state.password} />
        <button className="btn btn-lg btn-primary btn-block" type="button" onClick={this.doLogin}>Log in</button>
        {this.state.error && <div className="alert alert-danger" role="alert">{this.state.error}</div>}
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
                <a href="#" className="navbar-brand d-flex align-items-center">
                  <i className="fas fa-comments" />
                  <strong>Messages</strong>
                </a>
                <p style={{ color: 'white', marginTop: 16 }}>
                  {this.state.name} ({this.state.email})
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
                  <a href="#" onClick={this.send} className="btn btn-primary my-2"><i className="fas fa-paper-plane" /> Send</a>
                  <a href="#" onClick={this.reload} className="btn btn-success my-2" style={{ marginLeft: 5 }}><i className="fas fa-sync-alt" /> Reload messages</a>
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
        <button 
          type="button" className="btn btn-primary btn-sm" data-toggle="modal" data-target="#state-modal" 
          style={{ position: 'fixed', right: 135, bottom: 0, margin: 5 }}>server state</button>
        <button 
          onClick={e => this.client.clearState().then(e => window.location.reload())} 
          type="button" className="btn btn-danger btn-sm" style={{ position: 'fixed', right: 0, bottom: 0, margin: 5 }}>clear server state</button>
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

