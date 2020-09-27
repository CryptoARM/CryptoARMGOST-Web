const { Curl } = require('../../dist')
var fs = require('fs')

const curl = new Curl()
const url = 'https://testca2012.cryptopro.ru/ui/api/certrequest'
var name = 'g12'
var password = '9185543195'
var req = fs.readFileSync('./certreq.req').toString()

curl.setOpt(Curl.option.URL, url)

curl.setOpt(Curl.option.HTTPHEADER, [
  'Content-Type: application/octet-stream',
  'Authorization: Basic ' +
    Buffer.from(name + ':' + password).toString('base64'),
])

curl.setOpt(Curl.option.POSTFIELDS, req)

curl.on('end', (statusCode, body) => {
  console.log(body)
  curl.close()
})

curl.on('error', curl.close.bind(curl))

curl.perform()
