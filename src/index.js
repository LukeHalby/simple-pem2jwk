import * as asn from 'asn1js'
import { Base64 } from 'js-base64'
import { Buffer } from 'buffer'

const RSA_OID = '1.2.840.113549.1.1.1';

function str2ab(str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

const buffer2base64uri = buff => buff.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

const addOptions = (jwk, opts) => {
  if (opts.use && !['sig', 'enc'].includes(opts.use)) {
    throw Error('"use" must be either "sig" or "enc"')
  }
  return { ...jwk, ...opts }
}

const pem2jwk = (pem, opts) => {
  let kind = undefined
  let standard = undefined
  // fetch the part of the PEM string between header and footer
  const lines = pem
    .trim()
    .split('\n')
  const pemHeader = lines[0]
  const pemFooter = lines[lines.length - 1]

  if (pemHeader === '-----BEGIN RSA PRIVATE KEY-----' && pemFooter === '-----END RSA PRIVATE KEY-----') {
    kind = 'private'
    standard = 'PKCS#1';
  } else if (pemHeader === '-----BEGIN RSA PUBLIC KEY-----' && pemFooter === '-----END RSA PUBLIC KEY-----') {
    kind = 'public'
    standard = 'PKCS#1';
  } else if (pemHeader === '-----BEGIN PRIVATE KEY-----' && pemFooter === '-----END PRIVATE KEY-----') {
    kind = 'private';
    standard = 'PKCS#8';
  } else if (pemHeader === '-----BEGIN PUBLIC KEY-----' && pemFooter === '-----END PUBLIC KEY-----') {
    kind = 'public';
    standard = 'PKCS#8';
  } else {
    throw Error(`Headers not supported: ${pemHeader}\n ${pemFooter}`)
  }

  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)

  // base64 decode the string to get the binary data
  const binaryDerString = Base64.atob(pemContents)

  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString)
  const sequence = asn.fromBER(binaryDer)

  const fieldNames = {
    private: [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ],
    public: [ 'n', 'e' ]
  }

  let fieldValues = undefined;
  switch (standard) {
    case 'PKCS#1':
      fieldValues = kind === 'private'
        ? sequence.result.valueBlock.value.slice(1)
        : sequence.result.valueBlock.value;
      break;
    case 'PKCS#8':
      // ensure RSA
      const oidValues = kind === 'private'
        ? sequence.result.valueBlock.value[1].valueBlock.value[0].valueBlock.value
        : sequence.result.valueBlock.value[0].valueBlock.value[0].valueBlock.value;
      const oid = oidValues.map(x => x.toString()).join('.');
      if (oid !== RSA_OID) throw Error(`OID not supported: ${oid}`);

      fieldValues = kind === 'private'
        ? sequence.result.valueBlock.value[2].valueBlock.value[0].valueBlock.value.slice(1)
        : sequence.result.valueBlock.value[1].valueBlock.value[0].valueBlock.value;
      break;
  }

  const fields = fieldValues
    .map(x => x.valueBlock.valueHex)
    .map((val , i) => i === 1 || val.byteLength % 2 === 0 ? val : val.slice(1))
    .map(x => Buffer.from(x))
    .map(b => buffer2base64uri(b))
    .map((b64, i) => ({ [fieldNames[kind][i]]: b64 }))

  const jwk = Object.assign({}, ...fields, { kty: 'RSA' })
  const result = opts
    ? addOptions(jwk, opts)
    : jwk

  return result
}

export default pem2jwk
