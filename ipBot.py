import configparser
import sqlite3
import logging
import urllib3
import re
from telegram.ext import Updater, CommandHandler


class Config:

    def __init__(self, config_filename):
        self.__config = configparser.ConfigParser()
        self.__config.read(config_filename)
        self.token = ''
        self.auth_users_list = ''
        self.ip_file = ''
        self.db_file = ''
        self.log_file = ''
        self.logging_level = ''
        self.update_interval = ''
        self.welcome_message = ''
        self.goodbye_message = ''
        self.unauthorized_message = ''
        self.ip_message = ''

    def parse(self):
        main_section = self.__config['IPBOT']
        self.token = main_section.get('token', '').strip()
        self.auth_users_list = main_section.get(
            'auth_users_list', './auth_users_list')
        self.ip_file = main_section.get('ip_file', './ip')
        self.db_file = main_section.get('db_file', './ipBot.db')
        self.log_file = main_section.get('log_file', './ipBot.log')
        self.logging_level = main_section.get('logging_level', 'INFO')
        self.update_interval = main_section.getint('update_interval', '300')
        self.welcome_message = main_section.get(
            'welcome_message', 'Service started')
        self.goodbye_message = main_section.get(
            'goodbye_message', 'Service stopped')
        self.unauthorized_message = main_section.get(
            'unauthorized_message', 'Unauthorized user.')
        self.ip_message = main_section.get('ip_message', 'New IP: ')


def init_users_db(connection, auth_users_filename):
    """Initializes and populates the DB with the authorized users

        A DB table is created if necessary.
        the table is then populated with the users specified in
        AUTH_USERS_LIST. Each line in the file must be formatted as follows:
        <user_id> <username>

        Args:
            connection: an open connection to an sqlite DB
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


def read_ip_from_file(ip_filename):
    """Reads and returns the ip from the file

        Returns:
            A string with the IP or an empty string in case of missing file or
            malformed IP.
    """
    try:
        with open(ip_filename, 'r') as in_file:
            line = in_file.readline()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
            return line
        return ''
    except:
        logging.info("File %s not found, it will be created" % (ip_filename))
        return ''


def is_ip_changed():
    """Checks if the IP has changed, if so it updates the global variable and the IP_FILE"""
    global ip
    http = urllib3.PoolManager()
    r = http.request("GET", 'http://wgetip.com')
    new_ip = r.data.decode("ascii")
    if new_ip == ip:
        return False
    ip = new_ip
    try:
        with open(IP_FILE, 'w') as out_file:
            out_file.write(ip)
    except:
        logging.warning('Unable to write the update ip on file %s' % (IP_FILE))
    return True


def is_authorized(connection, userid, username):
    """Checks if the user is authorized to use the service.

    Args:
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


def start(bot, update, db_filename, welcome_message, unauth_message):
    """Sets as active the IP update service"""
    userid = update.message.from_user['id']
    username = update.message.from_user['username']
    conn = sqlite3.connect(db_filename)
    if is_authorized(conn, userid, username):
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                        SET send = 1
                        WHERE userid=?''', (userid,))
        conn.commit()
        bot.send_message(chat_id=update.message.chat_id, text=welcome_message)
        bot.send_message(chat_id=update.message.chat_id, text='IP: %s' % (ip))
    else:
        logging.info("Unauthorized user")
        bot.send_message(chat_id=update.message.chat_id,
                         text=unauth_message)
    conn.close()


def stop(bot, update, db_filename, goodbye_message, unauth_message):
    """Set as inactive the IP update service"""
    userid = update.message.from_user['id']
    username = update.message.from_user['username']
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


def send_ip_update(bot, job, db_filename, ip_message):
    """If the IP has changed it sends it to all the active users

    Using the is_ip_changed function it decides whether to send the update.
    The update is sent to all the active users. An user become active if she
    is authorized and she sent the /start command, until she sends the /stop
    command.
    """
    global ip
    logging.info('sending recurrent update')
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute('SELECT userid FROM users WHERE send=1')
    userid_list = [x[0] for x in cursor.fetchall()]
    conn.close()
    if is_ip_changed():
        ip_message = ip_message + ip
        logging.info('IP changed')
        for user in userid_list:
            bot.send_message(chat_id=user, text=ip_message)


"""
ENTRY POINT
"""

configuration = Config('./config')
configuration.parse()
updater = Updater(token=configuration.token)
dispatcher = updater.dispatcher
job_queue = updater.job_queue

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO)

connection = sqlite3.connect(configuration.db_file)
init_users_db(connection, configuration.auth_users_list)
connection.close()
ip = read_ip_from_file(configuration.ip_file)

start_handler = CommandHandler('start',
                               lambda bot, update:
                               start(bot, update, configuration.db_file, configuration.welcome_message, configuration.unauthorized_message))

stop_handler = CommandHandler('stop',
                              lambda bot, update:
                              stop(bot, update, configuration.db_file, configuration.goodbye_message, configuration.unauthorized_message))

dispatcher.add_handler(start_handler)
dispatcher.add_handler(stop_handler)

job_minute = job_queue.run_repeating(lambda bot, job:
                                     send_ip_update(bot, job, configuration.db_file, configuration.ip_message), interval=configuration.update_interval, first=0)
updater.start_polling()
updater.idle()
