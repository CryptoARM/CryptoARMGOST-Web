# trusted-curl<!-- omit in toc -->

[Libcurl](https://github.com/curl/curl) bindings for Node.js.
_Based on the work from [jiangmiao/node-curl](https://github.com/jiangmiao/node-curl)._

- [Quick Start](#quick-start)
  - [Install](#install)
  - [Simple Request - Async / Await](#simple-request---async--await)
  - [Simple Request](#simple-request)
- [API](#api)
- [Detailed Installation](#detailed-installation)
  - [Building on Linux](#building-on-linux)
  - [Building on macOS](#building-on-macos)
    - [Xcode &gt;= 10 | macOS Mojave](#xcode-gt-10--macos-mojave)
  - [Building on Windows](#building-on-windows)
  - [Electron](#electron--nwjs)
    - [electron (aka atom-shell)](#electron-aka-atom-shell)
- [Getting Help](#getting-help)
- [Contributing](#contributing)

## Quick Start

### Install
windows
```bat
git clone https://github.com/TrustedPlus/trusted-curl.git
cd ./trusted-curl
git checkout whitelist
npm install --build-from-source --curl_include_dirs="D:\\curl\\builds\\libcurl-vc15-x64-release-static-ipv6-sspi-winssl\\include" --curl_libraries="D:\\curl\\builds\\libcurl-vc15-x64-release-static-ipv6-sspi-winssl\\lib\\libcurl_a.lib"
tsc
```
linux
```shell
git clone https://github.com/TrustedPlus/trusted-curl.git
cd ./trusted-curl
git checkout whitelist
npm install --build-from-source --curl_include_dirs="/opt/cprocsp/include" --curl_libraries="/opt/cprocsp/lib/amd64/libcpcurl.so"
tsc
```
macos
```shell
git clone https://github.com/TrustedPlus/trusted-curl.git
cd ./trusted-curl
git checkout whitelist
npm install --build-from-source --curl_include_dirs="/opt/cprocsp/include"
tsc
```
### Simple Request - Async / Await
> this API is experimental and is subject to changes without a major version bump

```javascript
const { curly } = require('trusted-curl');

const { statusCode, data, headers } = await curly.get('http://www.google.com')
```

### Simple Request
```javascript
const { Curl } = require('trusted-curl');

const curl = new Curl();

curl.setOpt('URL', 'www.google.com');
curl.setOpt('FOLLOWLOCATION', true);

curl.on('end', function (statusCode, data, headers) {
  console.info(statusCode);
  console.info('---');
  console.info(data.length);
  console.info('---');
  console.info(this.getInfo( 'TOTAL_TIME'));
  
  this.close();
});

curl.on('error', curl.close.bind(curl));
curl.perform();
```

#### Setting HTTP headers

Pass an array of strings specifying headers
```javascript
curl.setOpt(Curl.option.HTTPHEADER,
  ['Content-Type: application/x-amz-json-1.1'])
```

## API

The code provides Typescript type definitions, which should document most of the API.

Almost all [CURL options](https://curl.haxx.se/libcurl/c/curl_easy_setopt.html) are supported, if you pass one that is not, an error will be thrown.

For more usage examples check the [examples folder](./examples).

## Detailed Installation

The latest version of this package has prebuilt binaries (thanks to [node-pre-gyp](https://github.com/mapbox/node-pre-gyp/)) 
 available for:
* node.js: Latest two versions on active LTS (see https://github.com/nodejs/Release)
* electron v5, v4 and v3
* following platforms:
* Linux 64 bits
* Mac OS X 64 bits
* Windows 32 and 64 bits

### Building on Linux

To build the addon on linux based systems you must have:
- gcc >= 4.8
- python 2.7
- cryptopro csp 5.0 with dev package

### Building on macOS

On macOS you must have:
- macOS >= 10.12 (Sierra)
- Xcode Command Line Tools
- cryptopro csp 5.0 with dev package

You can check if you have Xcode Command Line Tools be running:
```sh
xcode-select -p
```

It should return their path, in case it returns nothing, you must install it by running:
```sh
xcode-select --install
```

#### Xcode >= 10 | macOS Mojave
In case you have errors installing the addon from source, and you are using macOS Mojave, check if the error you are receiving is the following one:
```
  CXX(target) Release/obj.target/node_libcurl/src/node_libcurl.o
  clang: error: no such file or directory: '/usr/include'
```

If that is the case, it's because newer versions of the Command Line Tools does not add the `/usr/include` folder by default. Check [Xcode 10 release notes](https://developer.apple.com/documentation/xcode_release_notes/xcode_10_release_notes#3035624) for details.

To fix this you need to install the separated package for the headers file:
```
open /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_10.14.pkg
```

To ignore the UI and install directly from the command line, use:
```
sudo installer -pkg /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_10.14.pkg -target /
```

After that you can try to install `trusted-curl` again.

### Building on Windows

If installing using a prebuilt binary you only need to have the [visual c++ 2017 runtime library](https://visualstudio.microsoft.com/downloads/#microsoft-visual-c-redistributable-for-visual-studio-2017).

If building from source, you must have:
- Python 2.7
- [Visual Studio >= 2017](https://visualstudio.microsoft.com/downloads/)
- [nasm](https://www.nasm.us/)
- prebuild libcurl

Python 2.7 and the Visual Studio compiler can be installed by running:
```sh
npm install --global --production windows-build-tools
```

`nasm` can be obtained from their website, which is linked above, or using chocolatey:
```
cinst nasm
```

### Electron

If building for a `Electron` you need to pass additional parameters to the install command.

If you are trying to use the prebuilt binary (if available), do not pass the `npm_config_build_from_source=true` / `--build-from-source` below.

#### electron (aka atom-shell)

> yarn
```bash
npm_config_build_from_source=true npm_config_runtime=electron npm_config_target=$(yarn --silent electron --version) npm_config_disturl=https://atom.io/download/atom-shell yarn add trusted-curl
```

> npm
```bash
npm install trusted-curl --build-from-source --runtime=electron --target=$(yarn --silent electron --version) --disturl=https://atom.io/download/atom-shell --save
```

Where `target` is the version of electron you are using, in our case, we are just using the version returned by the locally installed `electron` binary.

You can also put those args in a .npmrc file, like so:

```bash
runtime = electron
target = 5.0.1
target_arch = x64
dist_url = https://atom.io/download/atom-shell
```

## Getting Help

If your question is directly related to the addon or their usage, post a question on [Issues](https://github.com/TrustedPlus/trusted-curl/issues)

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md)

