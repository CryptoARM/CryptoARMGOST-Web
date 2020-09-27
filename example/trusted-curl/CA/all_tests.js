var assert = require('assert')
var crypto = require('crypto')
var trusted = require('trusted-crypto')
var fs = require('fs')
const { Curl } = require('../../dist')

var login
var password
var certReqId

const curlGetUserAttr = new Curl()
const curlPostRegreq = new Curl()
const curlGetRegreq = new Curl()
const curlPostCertreq = new Curl()
const curlGetCertreq = new Curl()
const curlGetRawCert = new Curl()

function generateReq() {
  var certReq
  var ext
  var exts
  var oid
  var reqFile = 'certreq.req'

  certReq = new trusted.pki.CertificationRequest()

  exts = new trusted.pki.ExtensionCollection()

  oid = new trusted.pki.Oid('keyUsage')
  ext = new trusted.pki.Extension(
    oid,
    'critical,keyAgreement,dataEncipherment,nonRepudiation,digitalSignature',
  )
  exts.push(ext)

  oid = new trusted.pki.Oid('extendedKeyUsage')
  ext = new trusted.pki.Extension(oid, '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4')
  exts.push(ext)

  oid = new trusted.pki.Oid('1.3.6.1.4.1.311.21.7')
  ext = new trusted.pki.Extension(oid, '1.2.643.2.2.46.0.8')
  exts.push(ext)

  var atrs = [
    { type: 'C', value: 'RU' },
    { type: 'CN', value: crypto.randomBytes(16).toString('hex') },
    { type: 'L', value: 'Yoshkar-Ola' },
    { type: 'S', value: 'Mari El' },
    { type: 'O', value: 'TestTLSReq Org' },
    { type: '1.2.643.100.3', value: '12295279882' },
    { type: '1.2.643.3.131.1.1', value: '002465363366' },
  ]
  certReq.subject = atrs
  certReq.version = 2
  certReq.extensions = exts
  certReq.exportableFlag = true
  certReq.pubKeyAlgorithm = 'gost2012-256'
  certReq.containerName = crypto.randomBytes(16).toString('hex')
  certReq.save('./' + reqFile, trusted.DataFormat.PEM)
  trusted.utils.Csp.deleteContainer(certReq.containerName, 80)
}

const urlUserAttr =
  'https://testca2012.cryptopro.ru/ui/api/b1ca4992-d7cd-4f7e-b56e-a81e00db58ee/userattr'
const urlRegreq =
  'https://testca2012.cryptopro.ru/ui/api/b1ca4992-d7cd-4f7e-b56e-a81e00db58ee/regrequest'
const urlCertReq = 'https://testca2012.cryptopro.ru/ui/api/certrequest'

curlGetUserAttr.setOpt(Curl.option.URL, urlUserAttr)

curlGetUserAttr.on('end', (status, body) => {
  curlGetUserAttr.close()

  assert.equal(body !== null, true)
  console.log(body)
  const data = {
    Comment: '3',
    Description: '2',
    Email: 'login@email.ru',
    KeyPhrase: '1',
    OidArray: [
      {
        '2.5.4.3': crypto.randomBytes(16).toString('hex'),
      },
      {
        '2.5.4.10': 'organizationTLS',
      },
    ],
  }
  curlPostRegreq.setOpt(Curl.option.URL, urlRegreq)
  curlPostRegreq.setOpt(Curl.option.HTTPHEADER, [
    'Content-Type: application/json',
    'Accept: application/json',
  ])
  curlPostRegreq.setOpt(Curl.option.POSTFIELDS, JSON.stringify(data))

  curlPostRegreq.on('end', (statusCode, body) => {
    curlPostRegreq.close()

    assert.equal(body !== null, true)
    console.log(body)
    login = JSON.parse(body).RegRequest.Token
    password = JSON.parse(body).RegRequest.Password
    curlGetRegreq.setOpt(Curl.option.URL, urlRegreq)
    curlGetRegreq.setOpt(Curl.option.HTTPHEADER, [
      `Authorization: Basic ${Buffer.from(login + ':' + password).toString(
        'base64',
      )}`,
    ])
    curlGetRegreq.on('end', (statusCode, body) => {
      curlGetRegreq.close()

      assert.equal(body !== null, true)
      console.log(body)
      generateReq()
      var req = fs.readFileSync('./certreq.req').toString()
      curlPostCertreq.setOpt(Curl.option.URL, urlCertReq)
      curlPostCertreq.setOpt(Curl.option.HTTPHEADER, [
        'Content-Type: application/octet-stream',
        `Authorization: Basic ${Buffer.from(login + ':' + password).toString(
          'base64',
        )}`,
      ])
      curlPostCertreq.setOpt(Curl.option.POSTFIELDS, req)
      curlPostCertreq.on('end', (statusCode, body) => {
        curlPostCertreq.close()

        console.log(body)
        certReqId = JSON.parse(body).CertRequest.CertRequestId
        const url5CertReqId =
          'https://testca2012.cryptopro.ru/ui/api/certrequest/' + certReqId
        curlGetCertreq.setOpt(Curl.option.URL, url5CertReqId)
        curlGetCertreq.setOpt(Curl.option.HTTPHEADER, [
          `Authorization: Basic ${Buffer.from(login + ':' + password).toString(
            'base64',
          )}`,
        ])
        curlGetCertreq.on('end', (statusCode, body) => {
          console.log(body)
          curlGetCertreq.close()

          certReqId = JSON.parse(body).CertRequest.CertRequestId

          curlGetRawCert.setOpt(
            Curl.option.URL,
            `https://testca2012.cryptopro.ru/ui/api/certrequest/${certReqId}/rawcert`,
          )
          curlGetRawCert.setOpt(Curl.option.HTTPHEADER, [
            `Authorization: Basic ${Buffer.from(
              login + ':' + password,
            ).toString('base64')}`,
          ])

          let data = new Buffer('')

          curlGetRawCert.on('data', (chunk, curlInstance) => {
            data = Buffer.concat([data, chunk])
            return chunk.length
          })

          curlGetRawCert.on('end', (statusCode, body) => {
            if (statusCode === 200) {
              const cert = new trusted.pki.Certificate()

              cert.import(data)
              const pemCert = cert.export(trusted.DataFormat.PEM).toString()

              console.log(pemCert)
            }

            curlGetRawCert.close()
          })

          console.log('================ GET raw cert ================')
          curlGetRawCert.perform()
        })
        console.log('================ GET certrequest ================')
        curlGetCertreq.perform()
      })
      console.log('================ POST certrequest ================')
      curlPostCertreq.perform()
    })
    console.log('================= GET regrequest =================')
    curlGetRegreq.perform()
  })
  console.log('================= POST regrequest =================')
  curlPostRegreq.perform()
})
console.log('=============== GET user attributes ===============')
curlGetUserAttr.perform()

curlGetCertreq.on('error', curlGetCertreq.close.bind(curlGetCertreq))
curlPostCertreq.on('error', curlPostCertreq.close.bind(curlPostCertreq))
curlGetRegreq.on('error', curlGetRegreq.close.bind(curlGetRegreq))
curlPostRegreq.on('error', curlPostRegreq.close.bind(curlPostRegreq))
curlGetUserAttr.on('error', curlGetUserAttr.close.bind(curlGetUserAttr))
curlGetRawCert.on('error', curlGetRawCert.close.bind(curlGetRawCert))
