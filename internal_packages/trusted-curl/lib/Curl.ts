/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { EventEmitter } from 'events'
import { StringDecoder } from 'string_decoder'
import assert from 'assert'

const pkg = require('../package.json')

import {
  NodeLibcurlNativeBinding,
  EasyNativeBinding,
  FileInfo,
  HttpPostField,
} from './types'

import { Easy } from './Easy'
import { mergeChunks } from './mergeChunks'
import { parseHeaders, HeaderInfo } from './parseHeaders'
import {
  DataCallbackOptions,
  ProgressCallbackOptions,
  StringListOptions,
  CurlOptionName,
  SpecificOptions,
} from './generated/CurlOption'
import { CurlInfoName } from './generated/CurlInfo'

import { CurlCode } from './enum/CurlCode'
import { CurlFeature } from './enum/CurlFeature'
import { CurlGlobalInit } from './enum/CurlGlobalInit'
import { CurlGssApi } from './enum/CurlGssApi'

const bindings: NodeLibcurlNativeBinding = require("../lib/binding/trusted_curl.node")

// tslint:disable-next-line
const { Curl: _Curl } = bindings

if (
  !process.env.NODE_LIBCURL_DISABLE_GLOBAL_INIT_CALL ||
  process.env.NODE_LIBCURL_DISABLE_GLOBAL_INIT_CALL !== 'true'
) {
  // We could just pass nothing here, CurlGlobalInitEnum.All is the default anyway.
  const globalInitResult = _Curl.globalInit(CurlGlobalInit.All)
  assert(globalInitResult === 0 || 'Libcurl global init failed.')
}

const decoder = new StringDecoder('utf8')

const curlInstanceMap = new WeakMap<EasyNativeBinding, Curl>()

/**
 * Wrapper around {@link Easy} class with a more *nodejs-friendly* interface.
 *
 * @remarks
 *
 * Also see the Curl Interface definition for some overloaded methods.
 * The `setOpt` method here has `(never, never)` as type for their arguments because
 *  the overloaded methods are the ones with the correct signatures.
 *
 * @public
 */
class Curl extends EventEmitter {
  /**
   * Calls [curl_global_init()](http://curl.haxx.se/libcurl/c/curl_global_init.html)
   * For **flags** see the the enum `CurlGlobalInit`
   *
   * This is automatically called when the addon is loaded, to disable this, set the environment variable
   *  `NODE_LIBCURL_DISABLE_GLOBAL_INIT_CALL=false`
   */
  static globalInit = _Curl.globalInit

  /**
   * Calls [curl_global_cleanup()](http://curl.haxx.se/libcurl/c/curl_global_cleanup.html)
   *
   * This is automatically called when the process is exiting
   */
  static globalCleanup = _Curl.globalCleanup

  static getCount = _Curl.getCount

  static isVersionGreaterOrEqualThan = (
    x: number,
    y: number,
    z: number = 0,
  ) => {
    return _Curl.VERSION_NUM >= (x << 16) + (y << 8) + z
  }

  static defaultUserAgent = `trusted-curl/${pkg.version}`

  /**
   * Current libcurl version
   */
  static VERSION_NUM = _Curl.VERSION_NUM

  /**
   * Options to be used with `Easy.getInfo` or `Curl.getInfo`
   *
   * See the official documentation of [curl_easy_getinfo()](http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html)
   *  for reference.
   *
   * `CURLINFO_EFFECTIVE_URL` becomes `Curl.info.EFFECTIVE_URL`
   */
  static info = _Curl.info
  /**
   * Options to be used with `Easy.setOpt` or `Curl.setOpt`
   *
   * See the official documentation of [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   *  for reference.
   *
   * `CURLOPT_URL` becomes `Curl.option.URL`
   */
  static option = _Curl.option

  /**
   * Internal Easy handle being used
   */
  protected handle: EasyNativeBinding

  /**
   * Stores current response payload
   * This will not store anything in case the NO_DATA_STORAGE flag is enabled
   */
  protected chunks: Buffer[]
  protected chunksLength: number

  /**
   * Stores current headers payload
   * This will not store anything in case the NO_DATA_STORAGE flag is enabled
   */
  protected headerChunks: Buffer[]
  protected headerChunksLength: number

  protected features: CurlFeature

  /**
   * Whether this instance is running or not (called perform())
   */
  isRunning: boolean

  constructor(cloneHandle?: EasyNativeBinding) {
    super()

    const handle = cloneHandle || new Easy()

    this.handle = handle

    this.handle.onSocketEvent((error, events) => {
      const curlInstance = curlInstanceMap.get(this.handle)

      assert(
        curlInstance,
        'Could not retrieve curl instance from easy handle on onMessage callback',
      )

      if (error) {
        curlInstance!.onError(error, -1)
      } else {
        curlInstance!.onEnd()
      }
    })

    // callbacks called by libcurl
    handle.setOpt(
      Curl.option.WRITEFUNCTION,
      this.defaultWriteFunction.bind(this),
    )
    handle.setOpt(
      Curl.option.HEADERFUNCTION,
      this.defaultHeaderFunction.bind(this),
    )

    handle.setOpt(Curl.option.USERAGENT, Curl.defaultUserAgent)

    this.chunks = []
    this.chunksLength = 0
    this.headerChunks = []
    this.headerChunksLength = 0

    this.features = 0

    this.isRunning = false

    curlInstanceMap.set(handle, this)
  }

  protected defaultWriteFunction(chunk: Buffer, size: number, nmemb: number) {
    if (!(this.features & CurlFeature.NoDataStorage)) {
      this.chunks.push(chunk)
      this.chunksLength += chunk.length
    }

    this.emit('data', chunk, this)

    return size * nmemb
  }

  protected defaultHeaderFunction(chunk: Buffer, size: number, nmemb: number) {
    if (!(this.features & CurlFeature.NoHeaderStorage)) {
      this.headerChunks.push(chunk)
      this.headerChunksLength += chunk.length
    }

    this.emit('header', chunk, this)

    return size * nmemb
  }

  /**
   * Event called when an error is thrown on this handle.
   */
  onError(error: Error, errorCode: CurlCode) {
    this.isRunning = false

    this.chunks = []
    this.chunksLength = 0
    this.headerChunks = []
    this.headerChunksLength = 0

    this.emit('error', error, errorCode, this)
  }

  /**
   * Called when this handle has finished the request.
   */
  onEnd() {
    const isHeaderStorageEnabled = !(
      this.features & CurlFeature.NoHeaderStorage
    )
    const isDataStorageEnabled = !(this.features & CurlFeature.NoDataStorage)
    const isHeaderParsingEnabled =
      !(this.features & CurlFeature.NoHeaderParsing) && isHeaderStorageEnabled
    const isDataParsingEnabled =
      !(this.features & CurlFeature.NoDataParsing) && isDataStorageEnabled

    this.isRunning = false

    const dataRaw = isDataStorageEnabled
      ? mergeChunks(this.chunks, this.chunksLength)
      : Buffer.alloc(0)
    const headersRaw = isHeaderStorageEnabled
      ? mergeChunks(this.headerChunks, this.headerChunksLength)
      : Buffer.alloc(0)

    this.chunks = []
    this.chunksLength = 0

    this.headerChunks = []
    this.headerChunksLength = 0

    const data = isDataParsingEnabled ? decoder.write(dataRaw) : dataRaw
    const headers = isHeaderParsingEnabled
      ? parseHeaders(decoder.write(headersRaw))
      : headersRaw

    const { code, data: status } = this.handle.getInfo(Curl.info.RESPONSE_CODE)

    if (code !== CurlCode.CURLE_OK) {
      const error = new Error('Could not get status code of request')
      this.emit('error', error, code, this)
    } else {
      this.emit('end', status, data, headers, this)
    }
  }

  /**
   * Enables a feature, should not be used while a request is running.
   * Use `Curl.feature` for predefined constants.
   */
  enable(bitmask: CurlFeature) {
    if (this.isRunning) {
      throw new Error(
        'You should not change the features while a request is running.',
      )
    }

    this.features |= bitmask

    return this
  }

  /**
   * Disables a feature, should not be used while a request is running.
   * Use `Curl.feature` for predefined constants.
   */
  disable(bitmask: CurlFeature) {
    if (this.isRunning) {
      throw new Error(
        'You should not change the features while a request is running.',
      )
    }

    this.features &= ~bitmask

    return this
  }

  setOpt(optionIdOrName: never, optionValue: never): this {
    // we are using never as arguments here, because we want to make sure the client
    //  uses one of the overloaded types

    // special case for WRITEFUNCTION and HEADERFUNCTION callbacks
    //  since if they are set back to null, we must restore the default callback.
    let value = optionValue
    if (
      (optionIdOrName === Curl.option.WRITEFUNCTION ||
        optionIdOrName === 'WRITEFUNCTION') &&
      !optionValue
    ) {
      value = this.defaultWriteFunction.bind(this) as never
    } else if (
      (optionIdOrName === Curl.option.HEADERFUNCTION ||
        optionIdOrName === 'HEADERFUNCTION') &&
      !optionValue
    ) {
      value = this.defaultHeaderFunction.bind(this) as never
    }

    const code = this.handle.setOpt(optionIdOrName, value)

    if (code !== CurlCode.CURLE_OK) {
      throw new Error(
        code === CurlCode.CURLE_UNKNOWN_OPTION
          ? 'Unknown option given. First argument must be the option internal id or the option name. You can use the Curl.option constants.'
          : Easy.strError(code),
      )
    }

    return this
  }

  /**
   * Use `Curl.info` for predefined constants.
   * Official libcurl documentation: [curl_easy_getinfo()](http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html)
   */
  getInfo(infoNameOrId: CurlInfoName) {
    const { code, data } = this.handle.getInfo(infoNameOrId)

    if (code !== CurlCode.CURLE_OK) {
      throw new Error(`getInfo failed. Error: ${Easy.strError(code)}`)
    }

    return data
  }

  /**
   * The option XFERINFOFUNCTION was introduced in curl version 7.32.0,
   *  versions older than that should use PROGRESSFUNCTION.
   * If you don't want to mess with version numbers you can use this method,
   * instead of directly calling `Curl.setOpt`
   *
   * NOPROGRESS should be set to false to make this function actually get called.
   */
  setProgressCallback(
    cb:
      | ((
          dltotal: number,
          dlnow: number,
          ultotal: number,
          ulnow: number,
        ) => number)
      | null,
  ) {
    if (Curl.VERSION_NUM >= 0x072000) {
      this.handle.setOpt(Curl.option.XFERINFOFUNCTION, cb)
    } else {
      this.handle.setOpt(Curl.option.PROGRESSFUNCTION, cb)
    }

    return this
  }

  /**
   * Add this instance to the processing queue.
   * This method should be called only one time per request,
   *  otherwise it will throw an exception.
   */
  perform() {
    if (this.isRunning) {
      throw new Error('Handle already running!')
    }

    const result = this.handle.perform()

    if (result !== CurlCode.CURLE_OK) {
      this.emit('error', Easy.strError(result), result, this)
    } else {
      this.isRunning = true
      this.handle.monitorSocketEvents()
    }

    return this
  }

  /**
   * Close this handle.
   *
   * **NOTE:** After closing the handle, it should not be used anymore! Doing so will throw an exception.
   */
  close() {
    curlInstanceMap.delete(this.handle)

    this.removeAllListeners()

    this.handle.setOpt(Curl.option.WRITEFUNCTION, null)
    this.handle.setOpt(Curl.option.HEADERFUNCTION, null)

    this.handle.close()
  }
}

/**
 * Overloaded methods for the Curl class.
 */
interface Curl {
  on(
    event: 'data',
    listener: (this: Curl, chunk: Buffer, curlInstance: Curl) => void,
  ): this
  on(
    event: 'header',
    listener: (this: Curl, chunk: Buffer, curlInstance: Curl) => void,
  ): this
  on(
    event: 'error',
    listener: (
      this: Curl,
      error: Error,
      errorCode: CurlCode,
      curlInstance: Curl,
    ) => void,
  ): this
  on(
    event: 'end',
    listener: (
      this: Curl,
      status: number,
      data: string | Buffer,
      headers: Buffer | HeaderInfo[],
      curlInstance: Curl,
    ) => void,
  ): this
  on(event: string, listener: Function): this

  // START AUTOMATICALLY GENERATED CODE - DO NOT EDIT
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: DataCallbackOptions,
    value: ((data: Buffer, size: number, nmemb: number) => number) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: ProgressCallbackOptions,
    value:
      | ((
          dltotal: number,
          dlnow: number,
          ultotal: number,
          ulnow: number,
        ) => number)
      | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(option: StringListOptions, value: string[] | null): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: 'CHUNK_BGN_FUNCTION',
    value: ((fileInfo: FileInfo, remains: number) => number) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(option: 'CHUNK_END_FUNCTION', value: (() => number) | null): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: 'DEBUGFUNCTION',
    value: ((type: number, data: Buffer) => 0) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: 'FNMATCH_FUNCTION',
    value: ((pattern: string, value: string) => number) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: 'SEEKFUNCTION',
    value: ((offset: number, origin: number) => number) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: 'TRAILERFUNCTION',
    value: (() => string[] | false) | null,
  ): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(option: 'HTTPPOST', value: HttpPostField[] | null): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(option: 'GSSAPI_DELEGATION', value: CurlGssApi | null): this
  /**
   * Use `Curl.option` for predefined constants.
   *
   * Official libcurl documentation: [curl_easy_setopt()](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)
   */
  setOpt(
    option: Exclude<CurlOptionName, SpecificOptions>,
    value: string | number | boolean | null,
  ): this
  // END AUTOMATICALLY GENERATED CODE - DO NOT EDIT
}

export { Curl }
