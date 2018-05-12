# QUIC (WIP)

A QUIC server/client implementation in Node.js.

[![NPM version][npm-image]][npm-url]
[![Build Status][travis-image]][travis-url]
[![Downloads][downloads-image]][downloads-url]

## Google QUIC https://www.chromium.org/quic

## Demo

### QUIC without TLS

https://github.com/fidm/quic/blob/master/example/echo.js

```sh
node -r ts-node/register example/echo.js
```

## Road Map

1. Implement wire layout ✓
2. Implement stream, session, client and server ✓
3. Implement crypto layout (Doing)
4. Implement HTTP/2 client and server (ToDo)
5. Implement [IETF](https://www.ietf.org/) QUIC (ToDo)

## License

QUIC for Node.js is licensed under the [MIT](https://github.com/fidm/quic/blob/master/LICENSE) license.
Copyright &copy; 2018 FIdM.

[npm-url]: https://npmjs.org/package/quic
[npm-image]: http://img.shields.io/npm/v/quic.svg

[travis-url]: https://travis-ci.org/fidm/quic
[travis-image]: http://img.shields.io/travis/fidm/quic.svg

[downloads-url]: https://npmjs.org/package/quic
[downloads-image]: http://img.shields.io/npm/dm/quic.svg?style=flat-square
