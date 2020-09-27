/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import 'should'

import { Curl } from '../../lib'

const url = 'https://github.com'
// const url = 'https://gost.infotecs.ru'


describe('getInfo()', () => {
  let curl: Curl;

  beforeEach(() => {
    curl = new Curl()
    curl.setOpt('URL', url)
  })

  afterEach(() => {
    curl.close()
  })

  it('should not work with non-implemented infos', done => {
    curl.on('end', status => {
      if (status !== 200) {
        throw Error(`Invalid status code: ${status}`)
      }

      ; (() => {
        curl.getInfo(Curl.info.PRIVATE)
      }).should.throw(/^Unsupported/)

      done()
    })

    curl.on('error', done)

    curl.perform()
  });

  it('CERTINFO', done => {
    curl.setOpt("CERTINFO", true);
    curl.on('end', status => {
      if (status !== 200) {
        throw Error(`Invalid status code: ${status}`)
      }

      let certInfo: string | number | any[] | null = null;
      ; (() => {
        certInfo = curl.getInfo(Curl.info.CERTINFO);
        if ("string" === typeof (certInfo) || "number" === typeof (certInfo)) {
          done("Wrong returned type");
          return;
        }

        if (certInfo && (certInfo !== null)) {
          certInfo.should.not.be.equal(undefined, "Returned value shoud not be undefined");
          certInfo.should.not.be.equal(null, "Returned value shoud not be null");

          typeof (certInfo).should.not.be.equal("object", "Returned value must be array");

          if ("object" === typeof (certInfo)) {
            certInfo.length.should.not.be.equal(0, "Returned array must not be empty");
          }

          const result = certInfo.find((itm: string): boolean => itm.search("Cert:") === 0);
          result.should.not.be.equal(undefined, "Certificate not returned");
        }
      }).should.not.throw(); // Enexpected error while collecting cert info

      done();
    });

    curl.on('error', done);

    curl.perform();
  });
})
