# AmneziaWG Config Decoder & Encoder

Скрипт для преобразования конфигураций [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) в формат `vpn://` и обратно. Подразумевается, что у вас уже установлен Python 3.11.x

## Оглавление

- [Возможности](#возможности)
- [Установка](#установка)
- [Использование](#использование)
- [Заметки](#заметки)
- [Поддержка](#поддержка)

## Возможности

- Преобразование конфигураций в формате `.conf` в `vpn://`
- Обратное преобразование из формата `vpn://` в `.conf`

## Установка

Клонируйте репозиторий:

    git clone https://github.com/JB-SelfCompany/awg-decoder.git

  Перейдите в склонированный репозиторий:
  
    cd awg-decoder

  #### Опционально (рекомендуется устанавливать библиотеки в виртуальное окружение)

  Создайте и активируйте виртуальное окружение для Python:

    python3.11 -m venv myenv

  Активация виртуального окружения для Linux:
    
    source myenv/bin/activate

  Для Windows:
  
    python -m myenv\Scripts\activate

## Использование

Для кодирования файла в формате `.conf` в `vpn://` используйте следующую команду:

    python3.11 awg-decoder.py --encode test.conf -o vpn.txt

Для декодирования из формата `vpn://` в `.conf` используйте следующую команду:

    python3.11 awg-decoder.py --decode "vpn://..." -o decoded.conf

## Заметки

При использовании ключа `-o` (`--output`) можно указывать любой формат файла на ваш выбор. К примеру, `.txt` или `.vpn`. 

Так же, можно не использовать ключи для вывода в файл. К примеру, вывод команды следующей команды будет в консоли: 

`python3.11 awg-decoder.py --encode test.conf`

С декодированием аналогично. К примеру, вывод команды следующей команды будет в консоли. 

`python3.11 awg-decoder.py --decode "vpn://..."`

## Поддержка

Если у вас возникли вопросы или проблемы с установкой и использованием бота, создайте [issue](https://github.com/JB-SelfCompany/awg_bot/issues) в этом репозитории или обратитесь к разработчику.

- [Matrix](https://matrix.to/#/@jack_benq:shd.company)
