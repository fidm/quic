'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import Long from 'long'
import { suite, it } from 'tman'
import { ok, strictEqual, throws } from 'assert'
import { bufferFromBytes } from './common'
import { fnv1a64Hash, SourceToken } from '../src/internal/crypto'

suite('crypto', function () {
  it('fnv1a64Hash', function () {
    ok(bufferFromBytes([0xcb, 0xf2, 0x9c, 0xe4, 0x84, 0x22, 0x23, 0x25])
      .equals(fnv1a64Hash(Buffer.from(''))))
    ok(bufferFromBytes([0xaf, 0x63, 0xdc, 0x4c, 0x86, 0x01, 0xec, 0x8c])
      .equals(fnv1a64Hash(Buffer.from('a'))))
    ok(bufferFromBytes([0x08, 0x9c, 0x44, 0x07, 0xb5, 0x45, 0x98, 0x6a])
      .equals(fnv1a64Hash(Buffer.from('ab'))))
    ok(bufferFromBytes([0xe7, 0x1f, 0xa2, 0x19, 0x05, 0x41, 0x57, 0x4b])
      .equals(fnv1a64Hash(Buffer.from('abc'))))

    ok(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
      .equals(fnv1a64Hash(bufferFromBytes([0x07, 0x1e, 0x62, 0x37, 0x2c, 0x02, 0x40, 0x42, 0x14, 0x69]))))
    ok(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
      .equals(fnv1a64Hash(bufferFromBytes([0x30, 0x5e, 0x64, 0x66, 0x59, 0x24, 0x65, 0x64, 0x5f, 0x06]))))
    ok(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
      .equals(fnv1a64Hash(bufferFromBytes([0x7b, 0x3e, 0x68, 0x34, 0x5f, 0x71, 0x43, 0x2a, 0x13, 0x12]))))

    // quic.clemente.io
    const cert = `
MIIFAzCCA+ugAwIBAgISA4utenhsMgwc+KKan0R8ltT4MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODAzMTMxNzAzNTdaFw0x
ODA2MTExNzAzNTdaMBsxGTAXBgNVBAMTEHF1aWMuY2xlbWVudGUuaW8wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtKDgCZl6cMU2q98MbWDQ7/tL2N44T
+fGcK0gvQW3X+4dmiaYHXTZcsP2zrLmCC7q7fov6DhGFXH+ndfJEhD9E26wwb2iV
tnrqN4hKbmGFQ+tM4fqqLlvFEYk78kKSWdz5yuGT+JGoQKzjXEaLcBnIFa3bHZUv
BzzLXj+S/dFGiQ5qtNNa2/Ulm4+dYv9AYINS68B/yIr30XWxTOXLG3VLO6eBcbmG
6qmz7hAZvk6RaoAbE2F+Ww+t1NQDEgKFPp9QDiedSOVEaaujV19bVXk4C96s6uCP
jxpmNXS9Tk/5xuAhepXfCbGsc2Ti79977H5U6BsCCG0+EIJbpoK8QskTAgMBAAGj
ggIQMIICDDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGzqrE0cFJjXVakI+kFGnvsh
tGLBMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEB
BGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0
Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0
Lm9yZy8wGwYDVR0RBBQwEoIQcXVpYy5jbGVtZW50ZS5pbzCB/gYDVR0gBIH2MIHz
MAgGBmeBDAECATCB5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0dHA6
Ly9jcHMubGV0c2VuY3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMgQ2Vy
dGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0
aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUg
UG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9zaXRv
cnkvMA0GCSqGSIb3DQEBCwUAA4IBAQCYxe3ZJtGlqeMLIUsxtFmnpaT8SLNwOn7K
GRnct40cUcwFF7F3M+vH4vCNH8yCsdEWBWEuEv9QWxpAJMWjlrPwzsqsEfmhX73z
XH55VBUaJfkEtAJg3BC/QJt95rVXcqWwTQa4TI+wdBnUOg2Kc48/vnlJWFwNWUUT
e/T3A4hFafQZ/2RYKEyLimlxnd+yfSnh8hOb7XHDxdwqjeldFMbk9bcWtEQMaue3
+Mwn/3+RS/52VHTbBDUQ+Fu0oBJHPcL3bWiQLgC/KjRp2Qo9W64qbm9czYRxEg/v
PHzIpYf+KSXjGzbjWIXTfxK8ehouwH4LlSNdOoFqvJSl2Bf2H4mH
    `.replace(/\s/m, '')

    strictEqual(fnv1a64Hash(Buffer.from(cert, 'base64')).toString('hex'),
      Long.fromString('14021741750704909750', true, 10).toString(16))
  })

  it.skip('SourceToken', function () {
    const stk = new SourceToken()
    const buf = stk.encode('127.0.0.1')
    const tk = stk.decode(buf)
    strictEqual(tk.ip, '127.0.0.1')
    ok((Date.now() - tk.ts.valueOf()) <= 1000)

    throws(() => stk.decode(buf.slice(1)))
  })
})
