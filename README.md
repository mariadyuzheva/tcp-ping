# Утилита "tcping"

Автор: Дюжева Мария (mdyuzheva@gmail.com)


## Описание
Данное приложение является реализацией сетевой утилиты для проверки возможности
установки соединения с портом по протоколу TCP.


## Требования
* Python версии не ниже 3.6
* ОС Linux
* matplotlib для построения графика результатов работы программы


## Состав
* Консольная версия: tcping.py
* Модули: packet.py
* Тесты: tcping_test.py


## Консольная версия
Справка по запуску: "./tcping.py --help"

Пример запуска: "./tcping.py HOST PORT -n NUMBER -i INTERVAL -t TIMEOUT -g FILENAME -d"


## Подробности реализации
В основе лежит класс "packet.PortScanner", в котором реализованы функции для отправки
SYN-пакета и анализа принятого пакета. 
Классы "packet.Packet" и "packet.ReceivedPacket" отвечают за реализацию отправляемого и 
получаемого пакетов соответственно.

На модуль "packet" написаны тесты, их можно найти в "tcping_test.py".
Покрытие тестами по строкам составляет 96%.

	packet.py          113      4    96%   33-35, 100
