const { Curl } = require('../../dist')

const curl = new Curl()
const url =
  'https://testca2012.cryptopro.ru/ui/api/b1ca4992-d7cd-4f7e-b56e-a81e00db58ee/regrequest'
var name = 'g12'
var password = '9185543195'

curl.setOpt(Curl.option.URL, url)

curl.setOpt(Curl.option.HTTPHEADER, [
  'Authorization: Basic ' +
    Buffer.from(name + ':' + password).toString('base64'),
])

curl.on('end', (statusCode, body) => {
  console.log(body)
  curl.close()
})

curl.on('error', curl.close.bind(curl))

curl.perform()
