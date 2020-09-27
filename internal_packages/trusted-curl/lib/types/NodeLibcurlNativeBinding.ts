/**
 * Copyright (c) Jonathan Cardoso Machado. All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { CurlNativeBindingObject, EasyNativeBindingObject } from './'

export interface NodeLibcurlNativeBinding {
  Curl: CurlNativeBindingObject
  Easy: EasyNativeBindingObject
}
