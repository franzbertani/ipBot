# ipBot

A not so useful Telegram bot to receive updates on your IP address.

## Dependencies

This bot requires **sqlite3**, **urllib3**, **configparser** and **python-telegram-bot**, so `pip install` them.

## Configuration File

You must provide a `config` in the same folder of the python script.
There's a template in `config.template`, the only thing that you **must** provide is the *token*.
The token can be obtained by contacting the [@BotFather](https://t.me/BotFather). 

## Authorized users

This bot looks for the authorized user list in a file called `./auth_users_list`.
Only those users will be able to issue `/start` and `/stop` commands to the bot.
Each line in the file represent an user and **must** be formatted as follows:
```
<user_id> <username>
```

You can retrieve an user `user_id` by using another bot called [@userinfobot](https://t.me/userinfobot).

## Start and stop

Two super simple bash scripts are provided to start and stop the service.

- `./start.sh`
- `./stop.sh`


