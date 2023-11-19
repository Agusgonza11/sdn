import configparser

def read_configuration(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    if 'Config' in config:
        for key, value in config.items('Config'):
            if ',' in value:
                value_list = [item.strip() for item in value.split(',')]
                config.set('Config', key, ','.join(value_list))

        return config.items('Config')

def get_configuration_values(config_file='rules.ini'):
    config_items = read_configuration(config_file)
    configuration = dict(config_items)
    result = {}
    for key, value in configuration.items():
        if ',' in value:
            value_list = [item.strip() for item in value.split(',')]
            result[key] = value_list if key != 'incommunicable_hosts' else [tuple(map(int, item.split('-'))) for item in value_list]
        else:
            result[key] = value.split(',') if ',' in value else value
    return result
