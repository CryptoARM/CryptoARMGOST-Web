/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import 'should'

import { Curl } from '../../lib'

describe('SSL', () => {
  it('should work with GOST ssl site', done => {
    const curl = new Curl()

    curl.setOpt('URL', 'https://cpca20.cryptopro.ru/')

    curl.on('end', statusCode => {
      statusCode.should.be.equal(200)
      curl.close()
      done()
    })

    curl.on('error', error => {
      curl.close()
      done(error)
    })

    curl.perform()
  })

  it('should work with RSA ssl site', done => {
    const curl = new Curl()

    curl.setOpt('URL', 'https://example.com')

    curl.on('end', statusCode => {
      statusCode.should.be.equal(200)
      curl.close()
      done()
    })

    curl.on('error', error => {
      curl.close()
      done(error)
    })

    curl.perform()
  })
})
