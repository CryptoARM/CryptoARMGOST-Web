/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import 'should'

import { Curl } from '../../lib'

const url = 'http://example.com'

let curl: Curl

describe('setOpt()', () => {
  beforeEach(() => {
    curl = new Curl()
    curl.setOpt('URL', url)
  })

  afterEach(() => {
    curl.close()
  })

  it('should accept Curl.option constants', () => {
    curl.setOpt('URL', url)
  })

  it('should not accept invalid argument type', () => {
    const optionsToTest = [
      ['URL', 0],
      ['HTTPPOST', 0],
      ['POSTFIELDS', 0],
    ] as const

    let errorsCaught = 0

    for (const optionTuple of optionsToTest) {
      try {
        // @ts-ignore
        curl.setOpt.apply(curl, optionTuple)
      } catch (error) {
        errorsCaught += 1
      }
    }

    if (errorsCaught !== optionsToTest.length) {
      throw Error('Invalid option was accepted.')
    }
  })

  it('should not work with non-implemented options', () => {
    ;(() => {
      // @ts-ignore
      curl.setOpt(Curl.option.SSL_CTX_FUNCTION, 1)
    }).should.throw(/^Unsupported/)
  })

  describe('HTTPPOST', () => {
    it('should not accept invalid arrays', () => {
      try {
        // @ts-ignore
        curl.setOpt('HTTPPOST', [1, 2, {}])
      } catch (error) {
        return
      }

      throw Error('Invalid array accepted.')
    })

    it('should not accept invalid property names', () => {
      try {
        // @ts-ignore
        curl.setOpt('HTTPPOST', [{ dummy: 'property' }])
      } catch (error) {
        return
      }

      throw Error('Invalid property name accepted.')
    })

    it('should not accept invalid property value', () => {
      const args = [{}, [], 1, null, false, undefined]
      let invalidArgs: string[] = []

      for (const arg of args) {
        try {
          // @ts-ignore
          curl.setOpt('HTTPPOST', [{ name: arg }])
        } catch (error) {
          invalidArgs = [...invalidArgs, arg === null ? 'null' : typeof arg]
        }
      }

      if (invalidArgs.length !== args.length) {
        throw Error(
          `Invalid property value accepted. Invalid Args: ${JSON.stringify(
            invalidArgs,
          )}, Args: ${JSON.stringify(args)}`,
        )
      }
    })
  })
})
