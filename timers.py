import time
import random
import datetime
import threading

# A timer that stores a time delay (minutes, seconds, hours) that can be checked
# Interfaced by _BotTimers, and controlled by MixerBot
class Timer:

    def __init__(self, ttype):
        self.rawDelay  = None # The amount of time delayed after initialization
        self.timerType = None # "sec" or "min" or "hr"

        self.time_d = None

        self.random = False
        self.randRange = ()

        self.loop = False

        self.active = False
        # End declarations
    
        if ttype not in ("sec", "min", "hr"):
            raise ValueError("type needs to be \"sec\", \"min\", or \"hr\"")
        self.timerType = ttype

    def setupDiscreteTimer(self, delay, loop):
        self.loop = loop
        self.rawDelay = delay
        self.random = False
        self.setDelay(delay)
        self.active = True

    def setupRandomTimer(self, rrange, loop):
        self.loop = loop
        self.rawDelay = 0
        self.random = True
        self.randRange = rrange
        if len(self.randRange) != 2:
            raise ValueError("Timer random range needs two specified values.")
        
        self.setDelay(0)
        self.active = True

    # If the loop is a randomly generated range, the raw delay is ignored.
    def setDelay(self, delay):
        if self.random:
            if len(self.randRange) != 2:
                raise ValueError("Timer random range needs two specified values.")
            if not any([isinstance(x, int) for x in self.randRange]):
                raise ValueError("Random range must be two integer values.")
            delay = random.randint(self.randRange[0], self.randRange[1])

        now = datetime.datetime.now()
        if self.timerType == "sec":
            td = datetime.timedelta(seconds=delay)
            self.time_d = now + td
        elif self.timerType == "min":
            td = datetime.timedelta(minutes=delay)
            self.time_d = now + td
        elif self.timerType == "hr":
            td = datetime.timedelta(hours=delay)
            self.time_d = now + td
            
    def check(self):
        if not self.active:
            return False
        
        state = datetime.datetime.now() >= self.time_d

        if state:
            if self.loop:
                self.setDelay(self.rawDelay)
            else:
                self.active = False
                
        return state

# The main loop for bot timers. This will be run in a different thread to
# run in parallel with the main bot.
class BotTimers:

    def __init__(self):
        self.timerList = []

        # These are accesed from outside to change
        self.initialized = False # Controls the main loop
        self.active = False      # Controls whether timer functions will run

        self.lock = None         # Locking thread for main loop function
    
        self.thread = threading.Thread(target=self.__loop, args=())
        self.lock = threading.Lock()
        self.initialized = True

    def begin(self):
        self.active = True
        self.thread.start()

    def __loop(self):
        while self.initialized:
            del_q = []
            self.lock.acquire(True)
            for entry in self.timerList:
                if entry['timer'].check() and self.active and not entry['paused']:
                    entry['callback'](entry['args'])
                if not entry['timer'].active:
                    del_q.append(entry)
            for e in del_q:
                self.timerList.remove(e)
            self.lock.release()
            time.sleep(1)

