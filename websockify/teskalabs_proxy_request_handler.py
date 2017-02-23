import socket
from websockify import websocket
from websockify.websocketproxy import ProxyRequestHandler


class InvalidRequestException(Exception):
    pass
class InvalidNonceException(Exception):
    pass

class TLRAProxyRequestHandler(ProxyRequestHandler):


    def parse_request_uri(self):
        """ Parses the path and the request query
            
            Rquest must look like one of these:
                e.g.: /clientid/10.0.0.1?nonce=tlranonce
                e.g.: /clientid/10.0.0.1:6080?nonce=tlranonce
            Otherwise raises InvalidRequestException

            :raises InvalidRequestException: if request is invalid
            :return (string client_id, string/None target_ip, string/None target_port, list params):
        """
        import re
        from urlparse import urlparse

        # Parse path
        parse_res = urlparse(self.path)
        path = parse_res.path

        # /CLIENT_ID/TARGET_IP[:TARGET_PORT]
        r_client_id = r'[a-zA-Z0-9]+'
        r_ip = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
        r_port = r'\d+'
        uri_regex = re.compile(r'^\/('+r_client_id+r')\/('+r_ip+r')(\:('+r_port+r'))?$')
        
        match = uri_regex.match(path)
        if match is None:
            raise InvalidRequestException()

        # Query
        query = parse_res.query
        params = {}
        if query != '':
            for param in query.split('&'):
                param = param.split('=')
                params[param[0]] = param[1] if len(param) > 1 else None

        # client_id, target_ip, target_port, params
        return match.group(1), match.group(2), match.group(7), params


    def validate_nonce(self, nonce):
        """ Validates TLRA nonce

            Verifies time validity and integrity of a nonce issued by the SeaCat Panel

            :return boolean:
        """
        from .token import Token
 
        secret = ''
        if self.server.scp_config is not None:
            if self.server.scp_config.has_option("general", "secret"):
                secret = self.server.scp_config.get("general", "secret")

        try:
            token = Token(secret)
            token.parse(nonce)
            # Valid 5 minutes
            token.validate(max_age=300.0)
        except Exception as e:
            return False

        return True


    def do_socks4a_connect(self, tsock, client_id):
        """ Sends a SOCKS4A CONNECT command to an open socket

            :param socket.socket tsock: An opened socket
            :return boolean: Whether SOCKS4A connect was successful or not
        """
        from socks4a import SOCKS4A
        sock4a = SOCKS4A(tsock)

        if not sock4a.do_CONNECT(
            dest_port=5900,
            dest_ip="0.0.0.1",
            user_id="",
            remote_name=client_id):
            tsock.shutdown(socket.SHUT_RDWR)
            tsock.close()
            return False
        return True


    def validate_connection(self):
        """ Overrides the ProxyRequestHandler validate_connection
        """
        ProxyRequestHandler.validate_connection(self)


    def new_websocket_client(self):
        """ Called after a new WebSocket connection has been established.

            :throws AuthenticationError:
            :throws InvalidRequestException:
        """

        # Checking for a token is done in validate_connection()
        # Connect to the target
        if self.server.wrap_cmd:
            msg = "connecting to command: '%s' (port %s)" % (" ".join(self.server.wrap_cmd), self.server.target_port)
        elif self.server.unix_target:
            msg = "connecting to unix socket: %s" % self.server.unix_target
        else:
            msg = "connecting to: %s:%s" % (
                                    self.server.target_host, self.server.target_port)

        if self.server.ssl_target:
            msg += " (using SSL)"
        self.log_message(msg)


        # Parse artefacts from request path
        client_id, target_host, target_port, params = self.parse_request_uri()
        target_host = target_host if target_host is not None else self.server.target_host
        target_port = target_port if target_port is not None else self.server.target_port

        # Validate TLRA Nonce
        if not self.validate_nonce(params.get('tlra_nonce', '')):
            from .auth_plugins import AuthenticationError
            raise AuthenticationError('Invalid TLRA Nonce')

        # Create socket
        tsock = websocket.WebSocketServer.socket(target_host,
                                                target_port,
                connect=True, use_ssl=self.server.ssl_target, unix_socket=self.server.unix_target)

        # Socks4a CONNECT
        if not self.do_socks4a_connect(tsock, client_id):
            raise Exception("Socks4a CONNECT failed.")


        self.request.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        if not self.server.wrap_cmd and not self.server.unix_target:
            tsock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self.print_traffic(self.traffic_legend)

        # Start proxying
        try:
            self.do_proxy(tsock)
        except:
            if tsock:
                tsock.shutdown(socket.SHUT_RDWR)
                tsock.close()
                if self.verbose:
                    self.log_message("%s:%s: Closed target",
                            self.server.target_host, self.server.target_port)
            raise

