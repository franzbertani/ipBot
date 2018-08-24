import sqlite3
import logging
import urllib3
import re
from telegram.ext import Updater, CommandHandler

TOKEN_FILE = './token'
AUTH_USERS_LIST = './auth_users_list'
IP_FILE = './ip'
DB_FILE = './ipBot.db'


def init_users_db(connection):
    """Initializes and populates the db where userlist is stored

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
        with open(AUTH_USERS_LIST, 'r') as in_file:
            users_list = in_file.readlines()
        users_list = [x.strip() for x in users_list]
        users_list = [(int(x.split()[0]), x.split()[1]) for x in users_list]
    except:
        logging.warning('auth file not found or malformed')

    logging.info('Adding authorized users from %s' % (AUTH_USERS_LIST))
    for user in users_list:
        cursor.execute(
            'SELECT * FROM users WHERE userid=? and username=?', user)
        data = cursor.fetchone()
        if not data:
            cursor.execute('INSERT INTO users VALUES ( ?, ?, 0)', user)
        connection.commit()


def read_ip_from_file():
    """Read and return the ip from the IP_FILE

        Returns:
            A string with the IP or an empty string in case of missing file or
            malformed IP.
    """
    try:
        with open(IP_FILE, 'r') as in_file:
            line = in_file.readline()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
            return line
        return ''
    except:
        logging.info("File %s not found, it will be created" %(IP_FILE))
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


def is_authorized(userid, username):
    """Checks if the user is authorized to use the service.

    Args:
        userid: unique integer idenfier for the user, can be retrieved with @userinfobot.
        username: unique string username of the user.
    Returns:
        True or False, depending if the userid, username couple matches an existing user in the db.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM users WHERE userid=? and username=?', (userid, username))
    result = cursor.fetchone()
    conn.close()
    if result:
        return True
    return False


def start(bot, update):
    """Set as active the ip update service"""
    userid = update.message.from_user['id']
    username = update.message.from_user['username']
    if is_authorized(userid, username):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                        SET send = 1
                        WHERE userid=?''', (userid,))
        conn.commit()
        conn.close()
        bot.send_message(chat_id=update.message.chat_id, text="Hi there")
        bot.send_message(chat_id=update.message.chat_id, text='IP: %s' % (ip))
    else:
        logging.info("Unauthorized user")
        bot.send_message(chat_id=update.message.chat_id,
                         text="Unauthorized user.")


def stop(bot, update):
    """Set as inactive the ip update service"""
    userid = update.message.from_user['id']
    username = update.message.from_user['username']
    if is_authorized(userid, username):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''UPDATE users
                        SET send = 0
                        WHERE userid=?''', (userid,))
        conn.commit()
        conn.close()
        bot.send_message(chat_id=update.message.chat_id,
                         text="Stopped. See ya.")
    else:
        logging.info("Unauthorized user")
        bot.send_message(chat_id=update.message.chat_id,
                         text="Unauthorized user.")


def send_ip_update(bot, job):
    """If the IP has changed it sends it to all the active users

    Using the is_ip_changed function it decides whether to send the update.
    The update is sent to all the active users. An user become active if she
    is authorized and she sent the /start command, until she sends the /stop
    command.
    """
    global ip
    logging.info('sending recurrent update')
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT userid FROM users WHERE send=1')
    userid_list = [x[0] for x in cursor.fetchall()]
    conn.close()
    if is_ip_changed():
        logging.info('IP changed')
        for user in userid_list:
            bot.send_message(chat_id=user, text='new IP: %s' % (ip))


"""
ENTRY POINT
"""
bot_token = ''
try:
    with open(TOKEN_FILE, 'r') as in_file:
        bot_token = in_file.readline()
except:
    print("ERROR: no token found, put the bot token in %s" %(TOKEN_FILE))
    return
updater = Updater(token=TOKEN)
dispatcher = updater.dispatcher
job_queue = updater.job_queue

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO)

connection = sqlite3.connect(DB_FILE)
init_users_db(connection)
connection.close()
ip = read_ip_from_file()

start_handler = CommandHandler('start', start)
stop_handler = CommandHandler('stop', stop)
dispatcher.add_handler(start_handler)
dispatcher.add_handler(stop_handler)
job_minute = job_queue.run_repeating(send_ip_update, interval=60, first=0)
updater.start_polling()
updater.idle()
