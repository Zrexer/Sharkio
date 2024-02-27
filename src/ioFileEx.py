import time 
import os 

class FileIOException(object):
    def __init__(self, file_path: str = None):
        self.path = file_path
        self.callback_data = {}

    def verify(self, raiser: bool = True) -> dict:
        """
        for Download Requirements
        ---------------------------
        if Client does not Have that:
        ```
        from Sharkio.dls import DownloaderStream as DLS

        DLS.wireshark()
        ```
        """
        self.callback_data['check_time'] = time.ctime(time.time())
        if not os.path.exists(self.path):
            if raiser == True:
                raise FileExistsError("The '{}' Does not Exists".format(self.path))
            else:
                self.callback_data['error'] = True
                self.callback_data['base'] = "The '{}' Does not Exists".format(self.path)
                return self.callback_data
        else:
            if not raiser == True:
                self.callback_data['error'] = False
                return self.callback_data
