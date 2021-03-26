/*
MIT License

Copyright (c) 2021 Cyril Dever

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * From Ethereum's ECIES key path implementation, a Path should be a string formatted like `m/0'/0/0`
 * where the first part after the `m` is the account, the second is the scope and the last the key index.
 * 
 * NB: Account and scope shouldn't go over 2^16-1 (65535), keyIndex shouldn't go over 2^21-1 (2097151) in order to
 * to respect the current valueOf() algorithm on all devices.
 */
export interface Path {
  readonly account: string
  readonly scope: string
  readonly keyIndex: string
}

/**
 * KeyPath takes a path string and handles path manipulation (such as parsing it to a Path or getting the next path value)
 */
export interface KeyPath {
  readonly value: string
  parse: () => Path
  next: (increment?: number) => KeyPath
  valueOf: () => number
}

export const Path = (account: string, scope: string, keyIndex: string): Path => ({
  account,
  scope,
  keyIndex
})

const parse = (value: string): Path => {
  const parts = value.split('/')
  if (parts.length !== 4 || parts[0] !== 'm') {
    throw new Error('invalid value for path')
  }
  return Path(parts[1], parts[2], parts[3])
}

const next = (value: string, increment?: number): KeyPath => {
  const parsed = parse(value)
  const index = parseInt(parsed.keyIndex)
  const actualIncrement = increment !== undefined && increment > 1 ? increment : 1
  const newValue = 'm/' + parsed.account + '/' + parsed.scope + '/' + (index + actualIncrement).toString(10)
  return KeyPath(newValue)
}

const setValue = (value: string): string => {
  const parsed = parse(value)
  if (parseInt(parsed.account) > 2 ** 16 - 1 || parseInt(parsed.scope) > 2 ** 16 - 1 || parseInt(parsed.keyIndex) > 2 ** 21 - 1) {
    throw new Error('invalid path with value exceeding its limits')
  }
  return value
}

const valueOf = (value: string) => (): number => {
  const parsed = parse(value)
  return parseInt(parsed.account) * Math.pow(2, 37) + parseInt(parsed.scope) * Math.pow(2, 21) + parseInt(parsed.keyIndex)
}

/**
 * Build an immutable key path
 * 
 * @param {string} value - The path string
 * @returns an instance of KeyPath
 * @throws invalid value for path
 * @throws invalid path with value exceeding its limits
 */
export const KeyPath = (value: string): KeyPath => ({
  value: setValue(value),
  parse: () => parse(value),
  next: (increment?: number) => next(value, increment),
  valueOf: valueOf(value)
})
