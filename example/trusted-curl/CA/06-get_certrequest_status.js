const { Curl } = require('../../dist')

const curl = new Curl()
const url =
  'https://testca2012.cryptopro.ru/ui/api/certrequest/dda305a3-5942-420a-b317-aaca00dde8df' //{GUID}
//https://testca2012.cryptopro.ru/ui/api/certrequest/dda305a3-5942-420a-b317-aaca00dde8df/rawcert -- for binary output
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
