import configparser
import sqlite3
import logging
import urllib3
import re
from telegram.ext import Updater, CommandHandler


class Config:

    def __init__(self, config_filename):
        self._config = configparser.ConfigParser()
        self._config.read(config_filename)
        self.token = ''
        self.auth_users_list = ''
        self.ip_file = ''
        self.db_file = ''
        self.log_file = ''
        self.logging_level = 0
        self.update_interval = ''
        self.welcome_message = ''
        self.goodbye_message = ''
        self.unauthorized_message = ''
        self.ip_message = ''

    def parse(self):
        main_section = self._config['IPBOT']
        self.token = main_section.get('token', '').strip()
        self.auth_users_list = main_section.get(
            'auth_users_list', './auth_users_list')
        self.ip_file = main_section.get('ip_file', './ip')
        self.db_file = main_section.get('db_file', './ipBot.db')
        self.log_file = main_section.get('log_file', './ipBot.log')

        requested_logging_level = main_section.get('logging_level', 'info')
        if requested_logging_level.lower() == 'debug':
            self.logging_level = 10
        elif requested_logging_level.lower() == 'info':
            self.logging_level = 20
        elif requested_logging_level.lower() == 'warning':
            self.logging_level = 30
        elif requested_logging_level.lower() == 'error':
            self.logging_level = 40
        elif requested_logging_level.lower() == 'critical':
            self.logging_level = 50

        self.update_interval = main_section.getint('update_interval', 300)
        self.welcome_message = main_section.get(
            'welcome_message', 'Service started')
        self.goodbye_message = main_section.get(
            'goodbye_message', 'Service stopped')
        self.unauthorized_message = main_section.get(
            'unauthorized_message', 'Unauthorized user.')
        self.ip_message = main_section.get('ip_message', 'New IP: ')


class IP:

    def __init__(self, ip_filename):
        self._ip_filename = ip_filename
        self._stored_ip = ''
        try:
            with open(self._ip_filename, 'r') as in_file:
                line = in_file.readline()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                self._stored_ip = line
        except:
            logging.info("File %s not found or corrupted." %
                         (self._ip_filename))

    def get_ip(self):
        http = urllib3.PoolManager()
        r = http.request("GET", 'http://wgetip.com')
        new_ip = r.data.decode("ascii")

        has_changed = new_ip != self._stored_ip

        if has_changed:
            self._stored_ip = new_ip
            try:
                with open(self._ip_filename, 'w') as out_file:
                    out_file.write(self._stored_ip)
            except:
                logging.warning(
                    'Unable to write the update ip on file %s' % (ip_filename))

        return (self._stored_ip, has_changed)


def init_users_db(connection, auth_users_filename):
    """Initializes and populates the DB with the authorized users

        A DB table is created if necessary.
        the table is then populated with the users specified in the file passed as parameter.
        Each line in the file must be formatted as follows:
        <user_id> <username>

        Args:
            connection: an open connection to an sqlite DB
            auth_users_filename: path to the authorized users file
    """
    logging.info('Initializing users db')
    cursor = connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                    (userid INT PRIMARY KEY, username TEXT, send INT)''')
    connection.commit()
    users_list = []
    try:
        with open(auth_users_filename, 'r') as in_file:
            users_list = in_file.readlines()
        users_list = [x.strip() for x in users_list]
        users_list = [(int(x.split()[0]), x.split()[1]) for x in users_list]
    except:
        logging.warning('auth file not found or malformed')

    logging.info('Adding authorized users from %s' % (auth_users_filename))
    for user in users_list:
        cursor.execute(
            'SELECT * FROM users WHERE userid=? and username=?', user)
        data = cursor.fetchone()
        if not data:
            cursor.execute('INSERT INTO users VALUES ( ?, ?, 0)', user)
        connection.commit()


def is_authorized(connection, userid, username):
    """Checks if the user is authorized to use the service.

    Args:
        connection: an open connection to the sqlite DB whith auth users.
        userid: unique integer identifier for the user, can be retrieved with @userinfobot.
        username: unique string username of the user.
    Returns:
        True or False, depending if the userid, username couple matches an existing user in the DB.
    """
    cursor = connection.cursor()
    cursor.execute(
        'SELECT * FROM users WHERE userid=? and username=?', (userid, username))
    result = cursor.fetchone()
    if result:
        return True
    return False


def start(bot, update, ip, db_filename, welcome_message, unauth_message):
    """Sets as active the IP update service

        Args:
            bot: telegram bot.
            update: the update that triggered the command.
            ip: instance of class IP
            db_filename: path to the DB file with auth users.
            welcome_message: string with the message to welcome the new user.
            unauth_message: string with the message for the unauthorized error.
    """
    userid = update.message.from_user['id']
    username = update.message.from_user['username']

    """
    Here we must open a new connection since this function will run in a separate thread.
    Connections cannot be shared among threads.
    """
    conn = sqlite3.connect(db_filename)
    if is_authorized(conn, userid, username):
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                        SET send = 1
                        WHERE userid=?''', (userid,))
        conn.commit()
        bot.send_message(chat_id=update.message.chat_id, text=welcome_message)
        bot.send_message(chat_id=update.message.chat_id,
                         text='IP: %s' % (ip.get_ip()[0]))
    else:
        logging.info("Unauthorized user")
        bot.send_message(chat_id=update.message.chat_id,
                         text=unauth_message)
    conn.close()


def stop(bot, update, db_filename, goodbye_message, unauth_message):
    """Set as inactive the IP update service

        Args:
            bot: telegram bot.
            update: the update that triggered the command.
            db_filename: path to the DB file with auth users.
            goodbye_message: string with the message for the leaving user.
            unauth_message: string with the message for the unauthorized error.
    """
    userid = update.message.from_user['id']
    username = update.message.from_user['username']

    """
    Here we must open a new connection since this function will run in a separate thread.
    Connections cannot be shared among threads.
    """
    conn = sqlite3.connect(db_filename)
    if is_authorized(conn, userid, username):
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                        SET send = 0
                        WHERE userid=?''', (userid,))
        conn.commit()
        bot.send_message(chat_id=update.message.chat_id,
                         text=goodbye_message)
    else:
        logging.info("Unauthorized user")
        bot.send_message(chat_id=update.message.chat_id,
                         text=unauth_message)
    conn.close()


def send_ip_update(bot, job, ip, db_filename, ip_message):
    """If the IP has changed it sends it to all the active users

        The update is sent to all the active users. An user become active if she
        is authorized and she sent the /start command, until she sends the /stop
        command.

        Args:
            bot: telegram bot.
            job: telegram job queue.
            ip: instance of class IP
            db_filename: path to the DB file with auth users.
            ip_message: string with the message to notify the change.
    """
    logging.info('sending recurrent update')

    """
    Here we must open a new connection since this function will run in a separate thread.
    Connections cannot be shared among threads.
    """
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute('SELECT userid FROM users WHERE send=1')
    userid_list = [x[0] for x in cursor.fetchall()]
    conn.close()
    new_ip, is_ip_new = ip.get_ip()
    if is_ip_new:
        message = ip_message + new_ip
        logging.info('IP changed')
        for user in userid_list:
            bot.send_message(chat_id=user, text=message)


"""
ENTRY POINT
"""

configuration = Config('./config')
configuration.parse()
updater = Updater(token=configuration.token)
dispatcher = updater.dispatcher
job_queue = updater.job_queue

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=configuration.logging_level,
                    filename=configuration.log_file)

connection = sqlite3.connect(configuration.db_file)
init_users_db(connection, configuration.auth_users_list)
connection.close()
ip = IP(configuration.ip_file)

start_handler = CommandHandler('start',
                               lambda bot, update:
                               start(bot,
                                     update,
                                     ip,
                                     configuration.db_file,
                                     configuration.welcome_message,
                                     configuration.unauthorized_message))

stop_handler = CommandHandler('stop',
                              lambda bot, update:
                              stop(bot,
                                   update,
                                   configuration.db_file,
                                   configuration.goodbye_message,
                                   configuration.unauthorized_message))

dispatcher.add_handler(start_handler)
dispatcher.add_handler(stop_handler)

job_minute = job_queue.run_repeating(lambda bot, job:
                                     send_ip_update(bot,
                                                    job,
                                                    ip,
                                                    configuration.db_file,
                                                    configuration.ip_message),
                                     interval=configuration.update_interval,
                                     first=0)
updater.start_polling()
updater.idle()
