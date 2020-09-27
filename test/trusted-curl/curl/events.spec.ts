/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import 'should'

import { Curl, CurlCode } from '../../lib'

let curl: Curl

describe('Events', () => {
  beforeEach(() => {
    curl = new Curl()
    curl.setOpt('URL', 'http://example.com')
  })

  afterEach(() => {
    curl.close()
  })

  it('should emit "end" event when the connection ends without errors.', done => {
    curl.on('end', () => {
      done()
    })

    curl.on('error', error => {
      done(error)
    })

    curl.perform()
  })

  it('should emit "error" event when the connection fails', done => {
    curl.setOpt('URL', 'http://nodomain')
    curl.setOpt('FAILONERROR', true)

    curl.on('end', () => {
      done(Error('end event was called, but the connection failed.'))
    })

    curl.on('error', (error, errorCode) => {
      errorCode.should.be.of
        .type('number')
        .and.equal(CurlCode.CURLE_COULDNT_RESOLVE_HOST)

      done()
    })

    curl.perform()
  })

  it('should emit "error" when the connection is aborted in the progress cb', done => {
    curl.setProgressCallback(() => {
      return 1
    })

    curl.setOpt('NOPROGRESS', false)

    curl.on('end', () => {
      done(Error('end event was called, but the connection was aborted.'))
    })

    curl.on('error', error => {
      done()
    })

    curl.perform()
  })

  it('should emit "error" when the connection is aborted in the header cb', done => {
    curl.setOpt('HEADERFUNCTION', (_data, _size, _nmemb) => {
      return -1
    })

    curl.on('end', () => {
      done(Error('end event was called, but the connection was aborted.'))
    })

    curl.on('error', (error, errorCode) => {
      errorCode.should.be.of
        .type('number')
        .and.equal(CurlCode.CURLE_WRITE_ERROR)

      done()
    })

    curl.perform()
  })

  it('should emit "error" when the connection is aborted in the data cb', done => {
    curl.setOpt('WRITEFUNCTION', (_data, _size, _nmemb) => {
      return -1
    })

    curl.on('end', () => {
      done(Error('end event was called, but the connection was aborted.'))
    })

    curl.on('error', (error, errorCode) => {
      errorCode.should.be.of
        .type('number')
        .and.equal(CurlCode.CURLE_WRITE_ERROR)

      done()
    })

    curl.perform()
  })
})
