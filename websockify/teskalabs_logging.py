import os
import time
import logging
import socket
import logging.handlers

def logger_init(logger, opts):
	if opts.syslog:
		handler = logging.handlers.SysLogHandler(opts.syslog_socket)
		handler.setFormatter(RFC5424Formatter(app_name="websockify"))
		handler.setLevel(logging.INFO)
		logger.addHandler(handler)

class RFC5424Formatter(logging.Formatter):
	""" This formatter is meant for a SysLogHandler """

	def __init__(self, fmt=None, datefmt=None, app_name="-"):

		# RFC5424 format
		fmt = '{header} {structured_data} {message}'.format(
			header='{version} {timestamp} {hostname} {app_name} {proc_id} {msg_id}'.format(
				version="1",
				timestamp='%(asctime)s.%(msecs)dZ',
				hostname=socket.gethostname(),
				app_name=app_name,
				proc_id=os.getpid(),
				msg_id='-'),
			structured_data='',
			message='%(message)s'
		)

		# Initialize formatter
		super(RFC5424Formatter, self).__init__(
			fmt=fmt,
			datefmt='%Y-%m-%dT%H:%M:%S')

		# Convert time to GMT
		self.converter = time.gmtime
