const { Curl } = require('../../dist')

const curl = new Curl()
const url =
  'https://testca2012.cryptopro.ru/ui/api/certrequest/dda305a3-5942-420a-b317-aaca00dde8df' //{GUID}

var name = 'g12'
var password = '9185543195'

const data = {
  Status: 'K',
}

curl.setOpt(Curl.option.URL, url)

curl.setOpt(Curl.option.HTTPHEADER, [
  'Content-Type: application/json',
  'Accept: */*',
  'Authorization: Basic ' +
    Buffer.from(name + ':' + password).toString('base64'),
])

curl.setOpt(Curl.option.POSTFIELDS, JSON.stringify(data))

curl.on('end', (statusCode, body) => {
  console.log(body)
  curl.close()
})

curl.on('error', curl.close.bind(curl))

curl.perform()
