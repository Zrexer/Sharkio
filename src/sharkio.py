#!/usr/bin/env python3 
# SHARK IO

from rich import print as printer
import sys
import time
import os 
import ioFileEx

commands: dict = {}

# Copied From my Github: https://github.com/Zrexer/Bufferx
class BufferList(object):
    def __init__(self,
                 List: list = [],
                 ):
        
        self.list = List
        
    def parse(self):
        bfd = {}

        for i in range(len(self.list)):
            bfd["_"+str(i+1)] = self.list[i]

        return bfd
    
    def isexists(self, target):
        if target in self.list:
            return True
        else:return False
    
    def indexexists(self, target):
        if target in self.list:
            return self.list.index(target)
        else:return False

    def isinfrontof(self, target, indexes):
        isit = False

        if target in self.list:
            try:
                indx = self.list.index(target)
                if indx == indexes:
                    isit = True
                else:isit = False
            except Exception as e:return e
        
        return isit

# Copied From my Github: https://github.com/Zrexer/Bufferx
class BufferConsole(object):
    def __init__(self):
        self.data = []

    def __setcommands__(self, __key, __value):
        commands[__key] = __value
        return commands
    
    def getDictArgv(self):
        return BufferList(sys.argv).parse()
    
    def addFlag(self, *flags, mode: str = "in_front_of"):
        flg = list(flags)
        for i in range(len(flg)):
            self.__setcommands__(str(i+1), flg[i])

        if mode == "in_front_of":
            for key, val in BufferConsole().getDictArgv().items():
                if str(val) in flg:
                    keyx = int(str(key).replace("_", ""))
                    keyx += 1
                    if not f"_{keyx}" in BufferConsole().getDictArgv().keys():
                        self.data.append("Null")
                        pass
                    else:
                        self.data.append(BufferConsole().getDictArgv()[f"_{keyx}"])
                        pass
                
                else:
                    pass

            return self.data


class SharkIO(object):
    def __init__(self, tshark_path: str = None):
        self.tfp = tshark_path
        self.returner_data = {}

    def getInterfaces(self) -> dict:
        """
        Get Interfaces
        ~~~~~~~~~~~~~~
        return list of interfaces and exit
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -D".format(self.tfp))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-D / --list-interfaces"
                self.returner_data['to_do'] = "Get The INTERFACES and return"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def getDataLinkTypes(self):
        """
        Get Data Link Types
        ~~~~~~~~~~~~~~~~~~~
        return list of link-layer types of iface and exit
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -L".format(self.tfp))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-L / --list-data-link-types"
                self.returner_data['to_do'] = "return list of link-layer types of iface and exit"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def liveCaptureInterface(self, interface_name: str = None) -> dict:
        """
        Live Capture
        ~~~~~~~~~~~~
        name or idx of interface (def: first non-loopback)
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        if interface_name == None:
            self.returner_data['error_source'] = True
            self.returner_data['ERROR_EXCEPTION'] = "'interface_name' parameter cannot be empty"
            return self.returner_data

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -i {}".format(self.tfp, interface_name))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-i / --interface"
                self.returner_data['to_do'] = "Live Capture with interfaces"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def captureFilter(self, port: int = 80) -> dict:
        """
        Capture Filter 
        ~~~~~~~~~~~~~~
        packet filter in libpcap filter syntax
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -f \"port {}\"".format(self.tfp, port))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-f"
                self.returner_data['to_do'] = "packet filter in libpcap filter syntax"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def snapLen(self, interface_name: str = None, snap_length: int = 100):
        """
        Snap Length
        ~~~~~~~~~~~
        packet snapshot length (def: appropriate maximum) -> in tshark
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        if interface_name == None:
            self.returner_data['error_source'] = True
            self.returner_data['ERROR_EXCEPTION'] = "'interface_name' parameter cannot be empty"
            return self.returner_data

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -s {} -i {}".format(self.tfp, snap_length, interface_name))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-s -i => -s / --snapshot-length"
                self.returner_data['to_do'] = "packet snapshot length (def: appropriate maximum) -> in tshark"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def setBufferSize(self, buffer_size: int = 10000):
        """
        Set Buffer Size
        ~~~~~~~~~~~~~~~
        size of kernel buffer (def: 2MB)
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -B {}".format(self.tfp, buffer_size))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-B"
                self.returner_data['to_do'] = "packet snapshot length (def: appropriate maximum)"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def linkTypeInterface(self, interface_name: str = None, link_layer_type: str = "EN10MB"):
        """
        Link Layer Type
        ~~~~~~~~~~~~~~~
        link layer type (def: first appropriate)
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        if interface_name == None:
            self.returner_data['error_source'] = True
            self.returner_data['ERROR_EXCEPTION'] = "'interface_name' parameter cannot be empty"
            return self.returner_data

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} -i {} -y {}".format(self.tfp, interface_name, link_layer_type))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "-i -y => -y / --linktype"
                self.returner_data['to_do'] = "link layer type (def: first appropriate)"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
    def updateInterval(self, ms_time: int = 100):
        """
        Update Interval
        ~~~~~~~~~~~~~~~
        interval between updates with new packets (def: 100ms)
        """
        self.returner_data.clear()
        self.returner_data['start_time'] = time.ctime(time.time())

        res = ioFileEx.FileIOException(self.tfp).verify(False)
        if 'error' in res.keys() and res['error'] == True:
            return {"error" : True, "result" : res['base']}
        else:
            try:
                os.system("{} --update-interval {}".format(self.tfp, ms_time))
                self.returner_data['error_source'] = False
                self.returner_data['path_worker'] = os.getcwd()
                self.returner_data['file_name'] = sys.argv[0]
                self.returner_data['command'] = "--update-interval"
                self.returner_data['to_do'] = "interval between updates with new packets (def: 100ms)"
                return self.returner_data
            except Exception as ERROR_EXCEPTION:
                self.returner_data['error_source'] = True
                self.returner_data['ERROR_EXCEPTION'] = str(ERROR_EXCEPTION)
                return self.returner_data
            
