/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import 'should'

import { Curl } from '../../lib'

let curl: Curl

describe('setOpt() options from black list', () => {
  beforeEach(() => {
    curl = new Curl()
  })

  afterEach(() => {
    curl.close()
  })

  it('should not work with non-implemented options SSL_CTX_FUNCTION', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.SSL_CTX_FUNCTION, 1)
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_VERBOSE', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.VERBOSE, 1)
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_FTP_SSL_CCC', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.FTP_SSL_CCC, 1)
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_OPENSOCKETFUNCTION', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.OPENSOCKETFUNCTION, 1)
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY_KEYPASSWD', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY_KEYPASSWD, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_KEYPASSWD', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.KEYPASSWD, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_SSL_VERIFYPEER', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.SSL_VERIFYPEER, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY_SSL_VERIFYPEER', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY_SSL_VERIFYPEER, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_SSL_VERIFYHOST', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.SSL_VERIFYHOST, '2')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY_SSL_VERIFYHOST', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY_SSL_VERIFYHOST, '2')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_SSL_OPTIONS', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.SSL_OPTIONS, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY_SSL_OPTIONS', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY_SSL_OPTIONS, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY, 'http://proxy:80')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXYTYPE', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXYTYPE, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_HTTPPROXYTUNNEL', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.HTTPPROXYTUNNEL, 1)
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PRE_PROXY', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PRE_PROXY, '1')
    }).should.throw(/^Unsupported/)
  })

  it('should not work with non-implemented options CURLOPT_PROXY_TRANSFER_MODE', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.PROXY_TRANSFER_MODE, 1)
    }).should.throw(/^Unsupported/)
  })
})
