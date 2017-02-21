import re, ConfigParser
from .websocketproxy import WebSocketProxy
from .teskalabs_proxy_request_handler import TLRAProxyRequestHandler

class TLRAWebSocketProxy(WebSocketProxy):
    
    def __init__(self, RequestHandlerClass=TLRAProxyRequestHandler, *args, **kwargs):
        self.scp_config_file = kwargs.pop('scp_config_file', None)
        self.scp_config = self.parse_scp_config_file(self.scp_config_file)
        WebSocketProxy.__init__(self, RequestHandlerClass=RequestHandlerClass, *args, **kwargs)


    def parse_scp_config_file(self, config_file):
        """ Parses the SeaCat Panel config

        :param config_file: Path to the SCP config file
        """

        if config_file is None:
            return None

        config=ConfigParser.ConfigParser()
        config.SECTCRE = re.compile(r"\[ *(?P<header>[^]]+?) *\]")
        if config.read(config_file) == []:
            raise Exception('Couldn\'t read SeaCat Panel config file.')

        return config

