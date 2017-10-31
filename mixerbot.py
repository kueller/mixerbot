import re
import sys
import time
import json
import random
import threading
import websocket

from . import timers
from . import mixerconnect

class MixerBot:
    __PRINT_OPT_MSG   = 0b00000001
    __PRINT_OPT_WHISP = 0b00000010
    __PRINT_OPT_JOIN  = 0b00000100
    __PRINT_OPT_SELF  = 0b00001000
    __PRINT_OPT_NONE  = 0b00010000
    __PRINT_OPT_ERR   = 0b00100000
    __PRINT_OPT_OTHER = 0b01000000
    __PRINT_OPT_STATE = 0b10000000
    __PRINT_OPT_ALL   = 0b11101111

    def __init__(self):
        self.__authenticated = False
        self.__refresh_token = None
        self.__access_token  = None
        
        self.__authkey = None

        self.__connected = False # State of chat auth

        self.__channel_id = None
        self.__user_id    = None
        self.__endpoints  = None

        self.__configFile = None

        self.__printopts = 0b1100101  # Printing options        

        self.server     = None
        self.channel    = None
        self.username   = None

        self.__variables = {}

        self.__chat = None
        self.__timers = timers.BotTimers()
        self.__timercode = 0

        # Message callback functions
        self.__msgCallback     = None
        self.__whisperCallback = None
        self.__actionCallback  = None

        self.__key_refresh = threading.Thread(target=self.__auto_refresh_key,
                                              args=())
        self.__refresh_active = False

    def setInfoFromConfig(self, filename):
        try:
            with open(filename, 'r') as f:
                configLines = f.read().splitlines()
                configLines = list(configLines)
        except IOError:
            raise

        self.__configFile = filename
        
        for line in configLines:
            if line.startswith('#'):
                continue
            
            tokens = line.strip().lower().split()
            [cname, eq, cvalue] = line.lower().partition('=')

            if len(tokens) < 1:
                continue

            if tokens[0] == 'declare':
                if len(tokens) < 3:
                    raise IndexError("\"declare\" must have following type, name, and value")

                type_d = {'boolean': bool,
                          'string': str,
                          'number': int}

                vartype = tokens[1]
                varname = tokens[2]

                if vartype not in type_d:
                    raise ValueError("Unknown var type \"%s\"." % vartype)
                if re.fullmatch('[a-z][\w_]+', varname) == None:
                    raise ValueError(("Variable \"%s\" must start with a letter "
                                      "and can contain only alphanumeric characters "
                                      "and underscores." % varname))
                if varname in self.__variables:
                    raise KeyError("Variable \"%s\" already declared." % varname)

                self.__variables[varname] = {}
                self.__variables[varname]['value'] = None
                self.__variables[varname]['type']  = type_d[vartype]
            elif cname.strip() == 'channel':
                channel = cvalue.strip()
                self.channel = channel
            elif cname.strip() == 'username':
                username = cvalue.strip()
                self.username = username
            elif cname.strip() == 'authenticated':
                authenticated = cvalue.strip()
                self.__authenticated = authenticated.strip() == "true"
            elif cname.strip() == 'refresh_token':
                token = cvalue.strip()
                if token.isalnum():
                    self.__refresh_token = line.partition('=')[2].strip()
            elif re.fullmatch('(user|print)\.[a-z]+', cname.strip()) != None:
                namepath = cname.strip().split('.')
                option = cvalue.strip()
                self.__parseOptions(namepath, option)
            else:
                raise ValueError("Unknown option %s." % cname)
    
    # Parses the print.opt or user.var options
    def __parseOptions(self, namepath, value):
        if len(namepath) <= 1:
            raise IndexError("Missing variable name for \"%s\"." % '.'.join(namepath))

        if namepath[0] == 'user':
            varname = namepath[1]
            if varname not in self.__variables:
                raise KeyError("Variable \"%s\" not declared." % varname)
            if self.__variables[varname]['type'] == bool:
                if value not in ('true', 'false'):
                    raise TypeError("Variable \"%s\" not type boolean." % varname)
                self.__variables[varname]['value'] = value == 'true'
            elif self.__variables[varname]['type'] == str:
                self.__variables[varname]['value'] = value
            elif self.__variables[varname]['type'] == int:
                try:
                    self.__variables[varname]['value'] = int(value)
                except TypeError:
                    try:
                        self.__variables[varname]['value'] = float(value)
                        self.__variables[varname]['type'] = float
                    except TypeError:
                        raise TypeError("Variable \"%s\" not a valid number." % varname)
        elif namepath[0] == 'print':
            if value not in ('true', 'false'):
                raise TypeError("Print option \"%s\" not of type boolean" % namepath[2])
            opt = value == 'true'

            if namepath[1] == 'msg':
                self.setPrintOptions(msg=opt)
            elif namepath[1] == 'whisp':
                self.setPrintOptions(tag=opt)
            elif namepath[1] == 'join':
                self.setPrintOptions(join=opt)
            elif namepath[1] == 'selfmsg':
                self.setPrintOptions(selfmsg=opt)
            elif namepath[1] == 'none':
                self.setPrintOptions(none=opt)
            elif namepath[1] == 'err':
                self.setPrintOptions(err=opt)
            elif namepath[1] == 'other':
                self.setPrintOptions(other=opt)
            elif namepath[1] == 'state':
                self.setPrintOptions(state=opt)
            elif namepath[1] == 'allmsg':
                self.setPrintOptions(allmsg=opt)

    # Sets what will be printed to stdout.
    def setPrintOptions(self, **kwargs):
        for key in kwargs:
            if not isinstance(kwargs[key], bool):
                raise TypeError('setPrintOptions takes only bool values.')
            
        def toggle(key, opt):
            if not kwargs[key] and self.__printopts & opt != 0:
                self.__printopts = self.__printopts ^ opt
            elif kwargs[key] and self.__printopts & opt == 0:
                self.__printopts = self.__printopts | opt
        
        if 'msg' in kwargs:
            toggle('msg', self.__PRINT_OPT_MSG)
        elif 'whisp' in kwargs:
            toggle('tag', self.__PRINT_OPT_WHISP)
        elif 'join' in kwargs:
            toggle('join', self.__PRINT_OPT_JOIN)
        elif 'selfmsg' in kwargs: 
            toggle('selfmsg', self.__PRINT_OPT_SELF)
        elif 'none' in kwargs:
            toggle('none', self.__PRINT_OPT_NONE)
        elif 'err' in kwargs:
            toggle('err', self.__PRINT_OPT_ERR)
        elif 'other' in kwargs:
            toggle('other', self.__PRINT_OPT_OTHER)
        elif 'state' in kwargs:
            toggle('state', self.__PRINT_OPT_STATE)
        elif 'allmsg' in kwargs:
            if kwargs['allmsg']:
                self.__printopts = self.__PRINT_OPT_ALL
            else:
                self.__printopts = self.__PRINT_OPT_NONE

    def setCallbackFunctions(self, **kwargs):
        if 'msg' in kwargs:
            self.__msgCallback = kwargs['msg']
        if 'whisper' in kwargs:
            self.__whisperCallback = kwargs['whisper']
        if 'action' in kwargs:
            self.__actionCallback = kwargs['action']

    def __auto_refresh_key(self):
        count = 0
        while self.__refresh_active:
            # 5 hour wait then refresh the token
            if count == (5 * 60 * 60) // 5:
                auth = mixerconnect.refresh_access_token(self.__refresh_token)
                if auth is not None:
                    self.__access_token = auth["access_token"]
                    self.__refresh_token = auth["refresh_token"]
                
                    self.__edit_main_config("refresh_token", self.__refresh_token)
                    count = 0
            count = count + 1
            time.sleep(5)
        
     # Timer controls
    def initializeTimers(self):
        self.__timers = timers.BotTimers()
    def timersInitialized(self):
        return self.__timers is not None
    def startTimers(self):
        self.__timers.begin()
    def timersStarted(self):
        return self.__timers.active
    def pauseTimers(self):
        self.__timers.lock.acquire(True)
        self.__timers.active = False
        self.__timers.lock.release()
    def resumeTimers(self):
        self.__timers.lock.acquire(True)
        self.__timers.active = True
        self.__timers.lock.release()
    def killTimers(self):
        self.__timers.lock.acquire(True)
        self.__timers.initialized = False
        self.__timers.lock.release()
        self.__timers.lock.acquire(True) # Wait for thread to close
        self.__timers = None
    def addTimer(self, ttype, delay, callback,
                 args, rand=False, rrange=(), loop=False):

        t_entry = {}
        timer = timers.Timer(ttype)

        if rand:
            timer.setupRandomTimer(rrange, loop)
        else:
            timer.setupDiscreteTimer(delay, loop)

        t_entry['timer'] = timer
        t_entry['callback'] = callback
        t_entry['args'] = args
        t_entry['code'] = self.__timercode
        t_entry['paused'] = False

        # Lists are thread safe, and no existing data is modified
        self.__timers.timerList.append(t_entry)

        self.__timercode += 1
        return t_entry['code']
    def removeTimer(self, code):
        self.__timers.lock.acquire(True)
        for entry in self.__timers.timerList:
            if entry['code'] == code:
                entry['timer'].active = False
        self.__timers.lock.release()
    def pauseTimer(self, code):
        self.__timers.lock.acquire(True)
        for entry in self.__timers.timerList:
            if entry['code'] == code:
                entry['paused'] = True
        self.__timers.lock.release()
    def resumeTimer(self, code):
        self.__timers.lock.acquire(True)
        for entry in self.__timers.timerList:
            if entry['code'] == code:
                entry['paused'] = False
        self.__timers.lock.release()
    def timerExists(self, code):
        self.__timers.lock.acquire(True)
        for entry in self.__timers.timerList:
            if entry['code'] == code:
                self.__timers.lock.release()
                return True
        self.__timers.lock.release()
        return False
       
    def __edit_main_config(self, key, value):
        try:
            with open(self.__configFile, 'r') as f:
                configLines = f.read().splitlines()
                configLines = list(configLines)
        except IOError:
            raise

        done = False
        for i in range(len(configLines)):
            if configLines[i].strip().startswith(key):
                configLines[i] = key + " = " + value
                done = True

        if not done:
            configLines.append(key + " = " + value)

        try:
            with open(self.__configFile, 'w') as f:
                f.write('\n'.join(configLines))
        except IOError:
            raise
            
    def __shortcode_auth(self):
        code = mixerconnect.short_auth()
        if code == "":
            sys.exit(1)
            
        auth = mixerconnect.get_access_token(code)
        if auth is None:
            sys.exit("Failed to get access token from code.")

        self.__access_token = auth["access_token"]
        self.__refresh_token = auth["refresh_token"]

        self.__edit_main_config("authenticated", "true")
        self.__edit_main_config("refresh_token", self.__refresh_token)

    def start(self):
        print("Verifying authentication.")
        
        if any([x == None for x in (self.username, self.channel)]):
            raise ValueError("Username and channel must be set.")

        if self.__authenticated == False or self.__refresh_token is None:
            self.__shortcode_auth()
        else:
            auth = mixerconnect.refresh_access_token(self.__refresh_token)
            if auth is None:
                print("Refresh token failed to authenticate.")
                print("Restarting authentication process...\n")
                self.__shortcode_auth()
            else:
                self.__access_token = auth["access_token"]
                self.__refresh_token = auth["refresh_token"]

                self.__edit_main_config("refresh_token", self.__refresh_token)

        print("Setup connection to channel \"%s\"." % self.channel)

        self.__refresh_active = True
        self.__key_refresh.start()
        
        self.__channel_id = mixerconnect.get_channel_id(self.channel)
        self.__user_id = mixerconnect.get_user_id(self.username)

        header = {"Authorization": "Bearer %s" % self.__access_token}

        chatinfo = mixerconnect.get_chat_info(self.__channel_id, header)
        self.__endpoints = chatinfo["endpoints"]
        self.__authkey = chatinfo["authkey"]

        self.server = random.choice(self.__endpoints)

        self.__chat = websocket.WebSocketApp(self.server,
                                             on_message = self.__on_message,
                                             on_error = self.__on_error,
                                             on_close = self.__on_close)
        self.__chat.on_open = self.__on_open

        print("Joining channel \"%s\"." % self.channel)
        self.__chat.run_forever()

    # Takes the first 'data' attribute of events, and raw text if applicable
    def __printText(self, data, raw_text):
        if self.__printopts & self.__PRINT_OPT_NONE != 0:
            return

        to_print = False
        print_msg = ""

        if data["event"] == "ChatMessage":
            if data["data"]["message"]["meta"] == {}:
                to_print = self.__printopts & self.__PRINT_OPT_MSG != 0
            elif "me" in data["data"]["message"]["meta"]:
                to_print = self.__printopts & self.__PRINT_OPT_MSG != 0
            elif "whisper" in data["data"]["message"]["meta"]:
                to_print = self.__printopts & self.__PRINT_OPT_WHISP != 0

            if data["data"]["user_name"].lower() == self.username:
                to_print = self.__printopts & self.__PRINT_OPT_SELF != 0

            print_msg = "%s:  %s" % (data["data"]["user_name"], raw_text)
        elif data["event"] in ("UserJoin", "UserLeave"):
            to_print = self.__printopts & self.__PRINT_OPT_JOIN != 0
            print_msg = "%s:  %s" % (data["event"].replace("User", "").upper(),
                                    data["data"]["username"])
        elif data["event"] in ("PollStart", "PollEnd"):
            to_print = self.__printopts & self.__PRINT_OPT_OTHER != 0
            if data["event"] == "PollStart":
                print_msg = "\n%s (%s): \"%s\"\n%s\n" % (data["event"].upper(),
                                                         data["author"]["user_name"],
                                                         data["q"],
                                                         ','.join(data["answers"]))
            elif data["event"] == "PollEnd":
                print_msg = "\n%s (%s): \"%s\"\n%s\n" % (data["event"].upper(),
                                                         data["author"]["user_name"],
                                                         data["q"],
                                                         str(data["responses"]))
        elif data["event"] in ("DeleteMessage", "PurgeMessage"):
            to_print = self.__printopts & self.__PRINT_OPT_STATE != 0
            print_msg = "%s (%s)" % (data["event"].replace("Message", "").upper(),
                                     data["data"]["moderator"]["user_name"])
        elif data["event"] == "ClearMessages":
            to_print = self.__printopts & self.__PRINT_OPT_STATE != 0
            print_msg = "CLEAR (%s)" % data["data"]["clearer"]["user_name"]
        elif data["event"] == "UserUpdate":
            to_print = self.__printopts & self.__PRINT_OPT_STATE != 0
            print_msg = "UPDATE (%s)" % data["data"]["username"]
        elif data["event"] == "UserTimeout":
            to_print = self.__printopts & self.__PRINT_OPT_STATE != 0
            print_msg = "TIMEOUT (%s)" % data["data"]["user"]["user_name"]
        elif data["event"] == "Error":
            # This is custom built from the error websocket callback function.
            to_print = self.__printopts & self.__PRINT_OPT_ERR != 0
            print_msg = data["text"]

        if to_print:
            try:
                print(print_msg)
            except UnicodeDecodeError:
                None
        
    def __on_open(self, ws):
        auth_msg = {"type": "method",
                    "method": "auth",
                    "arguments": [self.__channel_id, self.__user_id, self.__authkey],
                    "id": 0}
        self.__chat.send(json.dumps(auth_msg))

    def __on_close(self, ws):
        sys.exit(0)

    def __on_error(self, ws, error):
        error_msg = {"event": "Error",
                     "text": error}
        self.__printText(error_msg, "")
        
    def __on_message(self, ws, text):
        data = json.loads(text)
        
        if not self.__connected:
            if data["type"] == "reply":
                if data["id"] == 0:
                    if data["error"] == None:
                        print("Connected.")
                        self.__connected = True
                    else:
                        print("Connection error: %s" % message["error"]["message"])
                        self.__chat.close()
        else:
            if data["type"] == "event":
                raw_text = ""
                
                if data["event"] == "ChatMessage":
                    message = data["data"]["message"]

                    textlist = []
                    for part in message["message"]:
                        if part["type"] in ("text", "tag"):
                            textlist.append(part["text"].strip())

                    raw_text = ' '.join(textlist)
                    command = raw_text.split(' ')[0]
                    argument = ''

                    if len(raw_text.split(' ')) > 1:
                        argument = raw_text.partition(' ')[2]

                    data["data"]["raw_text"] = raw_text.strip()
                    data["data"]["command"]  = command.strip()
                    data["data"]["argument"] = argument.strip()

                    if "whisper" in message["meta"]:
                        if self.__whisperCallback:
                            self.__whisperCallback(data["data"])
                    elif "me" in message["meta"]:
                        if self.__actionCallback:
                            self.__actionCallback(data["data"])
                    else:
                        if self.__msgCallback:
                            self.__msgCallback(data["data"])
                if data["event"] == "PollEnd":
                    None

                self.__printText(data, raw_text)

    # Bot interaction commands
    def msg(self, message):
        text = json.dumps({"type": "method",
                           "method": "msg",
                           "arguments": [ message ],
                           "id": 2})
        self.__chat.send(text)
    def whisper(self, username, message):
        text = json.dumps({"type": "method",
                           "method": "whisper",
                           "arguments": [ username, message ],
                           "id": 5})
        self.__chat.send(text)
    def startPoll(self, question, options, duration):
        text = json.dumps({"type": "method",
                           "method": "vote:start",
                           "arguments": [question, options, duration],
                           "id": 3})
        self.__chat.send(text)
    def timeout(self, username, duration):
        text = json.dumps({"type": "method",
                           "method": "timeout",
                           "arguments": [ username, duration ],
                           "id": 4})
        self.__chat.send(text)
    def purge(self, username):
        text = json.dumps({"type": "method",
                           "method": "purge",
                           "arguments": [ username ],
                           "id": 5})
        self.__chat.send(text)
    def deleteMessage(self):
        return # WIP
    def clearChat(self):
        text = json.dumps({"type": "method",
                           "method": "clearMessages",
                           "arguments": [],
                           "id": 11})
        self.__chat.send(text)
    def startGiveaway(self):
        text = json.dumps({"type": "method",
                           "method": "giveaway:start",
                           "arguments": [],
                           "id": 11})
        self.__chat.send(text)
    def close(self):
        self.__refresh_active = False
        self.__chat.close()

    # User variables
    def getUserVar(self, varname):
        if varname not in self.__variables:
            raise KeyError("Variable \"%s\" not found." % varname)
        return self.__variables[varname]['value']
    def setUserVar(self, varname, value):
        if varname not in self.__variables:
            raise KeyError("Variable \"%s\" not found." % varname)
        self.__variables[varname]['value'] = value
    def newUserVar(self, varname, value, vartype=None):
        if varname in self.__variables:
            raise KeyError("Variable \"%s\" already exists." % varname)
        if re.fullmatch('[a-z][\w_]+', varname) == None:
            raise ValueError(("Variable \"%s\" must start with a letter "
                              "and can contain only alphanumeric characters "
                              "and underscores." % varname))
        self.__variables[varname]['value'] = value
        self.__variables[varname]['type'] = vartype
    def delUserVar(self, varname):
        if varname not in self.__variables:
            raise KeyError("Variable \"%s\" not found." % varname)
        del self.__variables[varname]
    def getUserVarType(self, varname):
        if varname not in self.__variables:
            raise KeyError("Variable \"%s\" not found." % varname)
        return self.__variables[varname]['type']
    def setUserVarType(self, varname, vartype):
        if varname not in self.__variables:
            raise KeyError("Variable \"%s\" not found." % varname)
        self.__variables[varname]['type'] = vartype
