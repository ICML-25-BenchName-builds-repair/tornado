import logging
import re
from tornado.log import gen_log

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class DebugFilter(logging.Filter):
    def __init__(self, regex):
        super().__init__()
        self.regex = re.compile(regex)
        self.matched = 0
        
    def filter(self, record):
        message = record.getMessage()
        print(f"Filter called with message: {message!r}")
        match = bool(self.regex.match(message))
        print(f"  Match result: {match}")
        if match:
            self.matched += 1
            print(f"  Matched count: {self.matched}")
        return True  # Always let the message through for debugging

# Add our debug filter
debug_filter = DebugFilter(".*alert bad certificate")
gen_log.addFilter(debug_filter)

# Log some test messages
print("Logging test messages...")
gen_log.warning("Some other message")
gen_log.warning("alert bad certificate")
gen_log.warning("SSL Error with alert bad certificate")

# Check results
print(f"\nTotal matches: {debug_filter.matched}")