import configparser

def read_configuration(config_file):
    config = configparser.ConfigParser.ConfigParser()
    config.read(config_file)

    if 'Config' in config.sections():
        return config.items('Config')


def get_configuration_values(config_file='config.ini'):
    config_items = read_configuration(config_file)
    configuration = dict(config_items)

    return {
        'protocol': configuration.get('protocol'),
        'src_host': configuration.get('src_host'),
        'dst_host': configuration.get('dst_host'),
        'src_port': configuration.get('src_port'),
        'dst_port': configuration.get('dst_port')
    }