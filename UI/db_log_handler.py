import logging

db_default_formatter = logging.Formatter()

DJANGO_DB_LOGGER_ENABLE_FORMATTER = False

class DatabaseLogHandler(logging.Handler):
    def emit(self, record):
        from .models import StatusLog
        
        trace = None

        if record.exc_info:
            trace = db_default_formatter.formatException(record.exc_info)

        if DJANGO_DB_LOGGER_ENABLE_FORMATTER:
            msg = self.format(record)
        else:
            msg = record.getMessage()

        # Extract user information from the log message or other source
        user = None
        # Example: Extract user from log message
        if 'user' in record.__dict__:
            user = record.__dict__['user']
        
        kwargs = {
            'logger_name': record.name,
            'level': record.levelno,
            'msg': msg,
            'trace': trace,
            'user': user  # Pass the extracted user information
        }

        StatusLog.objects.create(**kwargs)

    def format(self, record):
        if self.formatter:
            fmt = self.formatter
        else:
            fmt = db_default_formatter

        if type(fmt) == logging.Formatter:
            record.message = record.getMessage()

            if fmt.usesTime():
                record.asctime = fmt.formatTime(record, fmt.datefmt)

            # ignore exception traceback and stack info

            return fmt.formatMessage(record)
        else:
            return fmt.format(record)
