/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { CurlGlobalInit } from '../enum/CurlGlobalInit'

import { CurlInfo } from '../generated/CurlInfo'
import { CurlOption } from '../generated/CurlOption'

export declare interface CurlNativeBindingObject {
  globalInit(flags: CurlGlobalInit): number
  getCount(): number
  globalCleanup(): void
  VERSION_NUM: number

  info: CurlInfo
  option: CurlOption
}
