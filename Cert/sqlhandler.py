import logging
import pymysql
from UI.models import LogEntry  # Import your LogEntry model

class MySQLDatabaseHandler(logging.Handler):
    def __init__(self, connection_params):
        super().__init__()
        self.connection_params = connection_params

    def emit(self, record):
        try:
            conn = pymysql.connect(**self.connection_params)
            cursor = conn.cursor()
            formatted_timestamp = record.created.strftime('%Y-%m-%d %H:%M:%S')  # Use record.created directly
            user_id = getattr(record, 'user', None)  # Get user ID if available, otherwise default to None
            cursor.execute(
                "INSERT INTO LogEntry (timestamp, message, user_id) VALUES (%s, %s, %s)",
                (formatted_timestamp, record.msg, user_id)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            # Log the error using the standard logging module
            self.handleError(record)

    def handleError(self, record):
        # Log the error message using the standard logging module
        logger = logging.getLogger(__name__)
        logger.exception("Error writing log to MySQL Database")
