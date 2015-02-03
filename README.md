## Synopsis

This chrome extension will support signing a server's blob as an alternate
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

## Demo

The Chrome extension is available on the [Google Web
Store](https://chrome.google.com/webstore/detail/keybase-login-extension/gjppgcifmgbfajbilocagcckghaogfme).


Once you have the extension installed, you can [try the demo
app](http://kb-login-ext.lrjn.flynnhub.com/)

If you are on a compatible website, the extension will appear in your URL bar
with the following image:
![Hello](https://raw.githubusercontent.com/jzila/kb-login-ext/master/chrome-ext/icon.png)

## Contributing

Feel free to submit pull requests or issues.

## License

Copyright 2015 John Zila

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#### [Node.JS License](https://raw.githubusercontent.com/joyent/node/v0.10.36/LICENSE)

#### [Kbpgp License](https://raw.githubusercontent.com/keybase/kbpgp/master/LICENSE)

#### [Triplesec License](https://raw.githubusercontent.com/keybase/triplesec/master/LICENSE)

#### [JQuery License](https://jquery.org/license/)
