# Сборка модуля

## Необходимое окружение

- Node.js v12.n LTS
- КриптоПро CSP 5  (на linux доустановить пакет разрабтчика)
- windows: поставить [windows-build-tools](https://www.npmjs.com/package/windows-build-tools)

## VS code extensions

Расширения нужны для единообразногго форматирования кода и статического анализа кода

- Name: Editor Config for VS Code (Id: chrisdias.vscodeeditorconfig)
- Name: ESLint (Id: dbaeumer.vscode-eslint)
- Name: TSLint (Id: ms-vscode.vscode-typescript-tslint-plugin)

## Сборка

```bash
> npm install

```

## Сборка для electron

```bash
> node-gyp rebuild --target=<electron_version> --arch=<arch> --dist-url=https://atom.io/download/electron

```

## Сборка с OCSP, TSP и CAdES SDK

### Установка SDK на Windows

Для установки TSP SDK и OCSP SDK на windows нужно скачать с сайта КриптоПро актуальные версии SDK:

<https://www.cryptopro.ru/products/pki/ocsp/sdk/downloads>

<https://www.cryptopro.ru/products/pki/tsp/sdk/downloads>

<https://www.cryptopro.ru/products/cades/downloads>

После чего нужно установить скачанные пакеты. При этом будут установлены необходимые для сборки файлы - заголовки и файлы lib для подключения библиотек.
Для запуска модуля этого недостаточно, поскольку с SDK не устанавливаются сами библиотеки для работы с OCSP и TSP. Для их установки нужно перейти в папку C:\Program Files (x86)\Crypto Pro\SDK\ и установить пакет cades-x64.msi или cades-win32.msi (в зависимости от разрядности модуля, который нужно будет запускать).

### Установка SDK на Linux

Для установки TSP SDK и OCSP SDK на linux нужно скачать с сайта КриптоПро актуальную версию SDK (входят в состав ЭЦП SDK):
<https://www.cryptopro.ru/products/cades/downloads>

Требуется установить пакеты cprocsp-pki-cades и lsb-cprocsp-devel (например cprocsp-pki-2.0.0-amd64-cades.rpm и lsb-cprocsp-devel-5.0.11535-4.noarch.rpm). Команды для установки пакетов, rpm:

```bash
rpm -i ./cprocsp-pki-2.0.0-amd64-cades.rpm
```

и DEB:

```bash
dpkg -i ./cprocsp-pki-cades_2.0.0-1_amd64.deb
```

По идее этого должно быть достаточно, но к сожалению пакеты КриптоПро почему-то устанавливают не все заголовки. Часть из них придётся скопировать вручную. Для этого нужно выкачать архив [additional-headers.tar.gz](https://yadi.sk/d/AyiSY5KWcb1meQ) и скопировать его содержимое в папку "/opt/cprocsp/include/pki"

### Установка SDK на Mac OS

Для установки TSP SDK и OCSP SDK на Mac OS нужно скачать с сайта КриптоПро актуальную версию SDK (входят в состав ЭЦП SDK):
<https://www.cryptopro.ru/products/cades/downloads>

Пакет устанавливает в систему приложение CryptoPro_ECP которое предоставляет Browser plug-in и содержит в себе TSP SDK, OCSP SDK и ЭЦП SDK.
