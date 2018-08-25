import configparser

config = configparser.ConfigParser()
config.read('./config')

main_section = config['IPBOT']
print(main_section['token'])
print(main_section['ip_file'])
print(main_section['welcome_message'])



