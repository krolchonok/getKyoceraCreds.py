# kyocera-cve-2022-1026
An unauthenticated data extraction vulnerability in Kyocera printers, which allows for recovery of cleartext address book and domain joined passwords.


## Vulnerability Overview
Back in 2021 while on a pen test, I was tinkering with Kyocera's thick client application used to remotely administer printers. While proxying traffic from the application, I discovered that Kyocera's SOAP API on port 9091/TCP did not properly handle authentication when performing sensitive actions. Kyocera MFPs can be configured to with bind credentials for company domains, FTP credentials, fileshare credentials, etc. Unauthenticated, it is possible to retrieve all credentials stored by the MFP, in cleartext.

My full writeup can be found on Rapid7's blog: https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/

## Exploit overview
I do not believe this is currently fixed in all models and remains a 0-day, despite reports to the vendor. I was only able to test on a couple of models identified over the years, but whenever I find a Kyocera printer, this still works.

The python script connects to the MFP on TCP port 9091 and issues a SOAP request to create a new address book export. The printer responds with the address book object number, and then the script sleeps for a few seconds while the book is finished being created. Finally, the book is retrieved via another SOAP request. Within the book you'll find all configured credentials in cleartext. 

Feel free to submit a PR with improved parsing, as I never came back around to beautifying the output or exploit process.

### Usage

```bash
# одиночный IP
python3 getKyoceraCreds.py 10.0.0.10

# несколько адресов через запятую или аргументами
python3 getKyoceraCreds.py 10.0.0.10,10.0.0.20 -i 10.0.0.30

# загрузка списка IP из файла (по одному в строке, поддерживаются строки через запятую)
python3 getKyoceraCreds.py -f ips.txt

# сохранение результата в файл
python3 getKyoceraCreds.py 10.0.0.10 -o result.txt
```

Скрипт выводит прогресс по каждому устройству и пытается разобрать SOAP-ответы, показывая поля
`login_name`, `login_password`, `email_address`, а при их отсутствии — подробные записи адресной книги
(имя, email, FTP/SMB серверы, логины и пароли, если заданы). Обнаруженные пароли дополнительно подсвечиваются
в выводе, а при использовании `-o/--output` все сообщения дублируются в указанный файл.

## Metasploit module

Файл `kyocera_address_book.rb` содержит вспомогательный модуль Metasploit,
повторяющий логику исходного скрипта. Чтобы воспользоваться им, поместите файл в
`modules/auxiliary/gather/` и загрузите в `msfconsole`:

```bash
# Быстрая установка через curl (Linux/macOS)
mkdir -p ~/.msf4/modules/auxiliary/gather/
curl -sL https://raw.githubusercontent.com/krolchonok/getKyoceraCreds.py/main/kyocera_address_book.rb -o ~/.msf4/modules/auxiliary/gather/kyocera_address_book.rb

# Или вручную
cp kyocera_address_book.rb $MSF_ROOT/modules/auxiliary/gather/
msfconsole -q
use auxiliary/gather/kyocera_address_book
set RHOSTS 10.0.0.10
run
```

Модуль автоматически создаёт экспорт адресной книги через SOAP, ждёт его готовности,
загружает результат, сохраняет XML в loot и выводит найденные учётные данные или
распарсенные записи адресной книги.

