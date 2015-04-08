## Synopsis

This Chrome extension will support signing a server's blob as an alternate
authentication method to individual server-based username/password login.

You must have a Keybase.io account with a public key hosted in order to 
use this extension.

There are two ways you can authenticate against your Keybase:

1. Host your encrypted private key on Keybase, and supply your Keybase.io
passphrase to the extension, which will then login to your keybase and
locally store your **encrypted** private key (or fail).
2. Supply the PGP-encrypted private key blob from your local machine.
The extension will locally store that encrypted private key.

Once your **encrypted** private key exists in local storage for the extension,
you can provide your key's passphrase to sign the server blob once.

## Dependencies

Requires [Redis](redis.io) to run the demo server.

## Demo

The Chrome extension is available on the [Google Web
Store](https://chrome.google.com/webstore/detail/keybase-login-extension/gjppgcifmgbfajbilocagcckghaogfme).

If you don't trust me (you shouldn't, that's what encryption is about!), you
can also install the Chrome extension from source by [following these
instructions](https://developer.chrome.com/extensions/getstarted#unpacked).

Once you have the extension installed, you can [try the demo
app](http://kb-login-ext.flynn.jzila.com/).

If you are on a compatible website (such as [the demo
app](http://kb-login-ext.flynn.jzila.com/), the extension will appear in your
URL bar with the following image:
![Hello](https://raw.githubusercontent.com/jzila/kb-login-ext/master/chrome-ext/icon.png)

## Building and Running

Once you've cloned the repository and have Redis available on the network, set
the environment variable `REDIS_HOST` to the hostname of your Redis instance.
If the environment variable is missing, it will default to `localhost`, but if
there is no Redis server at `localhost:6379`, it will crash.

Once you've satisfied the dependencies, run `npm start` from the root project
directory.

## Contributing

Feel free to submit pull requests or issues.

## License

The MIT License (MIT)

Copyright (c) 2015 John Zila

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

#### [Node.JS License](https://raw.githubusercontent.com/joyent/node/v0.10.36/LICENSE)

#### [Kbpgp License](https://raw.githubusercontent.com/keybase/kbpgp/master/LICENSE)

#### [Triplesec License](https://raw.githubusercontent.com/keybase/triplesec/master/LICENSE)

#### [JQuery License](https://jquery.org/license/)
