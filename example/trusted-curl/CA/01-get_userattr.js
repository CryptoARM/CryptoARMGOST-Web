const { Curl } = require('../../dist')

const curl = new Curl()
const url =
  'https://testca2012.cryptopro.ru/ui/api/b1ca4992-d7cd-4f7e-b56e-a81e00db58ee/userattr'

curl.setOpt(Curl.option.URL, url)

curl.perform()

curl.on('end', (status, data) => {
  console.log(data)
  curl.close()
})

curl.on('error', curl.close.bind(curl))
