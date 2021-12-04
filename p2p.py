 
# P2P 
class P2P:
    def __init__(self, _port: int, _max_clients: int = 1):
        #   
        self.running = True
        #  
        self.port = _port
        #  - 
        self.max_clients = _max_clients
        #  
        self.clients_ip = ["" for i in range(self.max_clients)]
        #    
        self.incoming_requests = {}
        #  
        self.clients_logs = [Log for i in range(self.max_clients)]
        #  
        self.client_sockets = [socket.socket() for i in range(self.max_clients)]
        #  
        for i in self.client_sockets:
            i.settimeout(0.2)
        #     
        self.keys = [rsa.key.PublicKey for i in range(self.max_clients)]
        #     
        self.my_keys = [rsa.key.PrivateKey for i in range(self.max_clients)]
        #   
        self.socket_busy = [False for i in range(self.max_clients)]
        #  
        self.blacklist = ["127.0.0.1"] + Log.read_and_return_list("blacklist.txt")
        #  
        self.server_socket = socket.socket()
        #  
        self.server_socket.settimeout(0.2)
        #  
        self.server_socket.bind(('localhost', _port))
        self.server_socket.listen(self.max_clients)
        self.log = Log("server.log")
        self.log.save_data("Server initialized")

    # server control

    #     
    def create_session(self, _address: str):
        self.log.save_data("Creating session with {}".format(_address))
        ind = self.__get_free_socket()
        if _address in self.blacklist:
            self.log.save_data("{} in blacklist".format(_address))
            return
        if ind is None:
            self.log.save_data("All sockets are busy, can`t connect to {}".format(_address))
            return
        try:
            self.__add_user(_address)
            thread = Thread(target=self.__connect, args=(_address, 1))
            thread.start()
            thread.join(0)
            connection, address = self.server_socket.accept()
            connection.settimeout(0.2)
        except OSError:
            self.log.save_data("Failed to create session with {}".format(_address))
            self.__del_user(_address)
            return
        my_key = rsa.newkeys(512)
        self.raw_send(_address, my_key[0].save_pkcs1())
        key = connection.recv(162).decode()
        self.clients_logs[ind].save_data("from {}: {}".format(_address, key))
        key = rsa.PublicKey.load_pkcs1(key)
        self.__add_keys(_address, key, my_key[1])
        while self.running and self.socket_busy[ind]:
            try:
                data = connection.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                self.close_connection(_address)
                return
            if data:
                data = rsa.decrypt(data, self.my_keys[ind])
                self.__add_request(_address, data)
        try:
            self.close_connection(_address)
        except TypeError or KeyError:
            pass

    #   
    def __connect(self, _address: str, *args):
        ind = self.__get_ind_by_address(_address)
        try:
            self.client_sockets[ind].connect((_address, self.port))
            self.socket_busy[ind] = True
            return True
        except OSError:
            return False

    #  
    def __reload_socket(self, _ind: int):
        self.client_sockets[_ind].close()
        self.client_sockets[_ind] = socket.socket()
        self.socket_busy[_ind] = False

    #  
    def close_connection(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.__del_key(_address)
        self.__reload_socket(ind)
        self.__del_user(_address)

    #  
    def kill_server(self):
        self.running = False
        sleep(1)
        self.server_socket.close()
        self.log.kill_log()
        for i in self.client_sockets:
            i.close()
        for i in self.clients_logs:
            try:
                i.kill_log()
            except TypeError:
                pass

    #    
    def send(self, _address: str, _message: str):
        ind = self.__get_ind_by_address(_address)
        try:
            self.clients_logs[ind].save_data("to {}: {}".format(_address, _message))
            self.client_sockets[ind].send(rsa.encrypt(_message.encode(), self.keys[ind]))
            self.log.save_data("Send message to {}".format(_address))
        except OSError:
            self.log.save_data("Can`t send message to {}".format(_address))

    #    
    def raw_send(self, _address: str, _message: bytes):
        ind = self.__get_ind_by_address(_address)
        try:
            self.client_sockets[ind].send(_message)
            self.clients_logs[ind].save_data("to {}: {}".format(_address, _message))
            self.log.save_data("Raw send message to {}".format(_address))
        except OSError:
            self.log.save_data("Raw send to {} Failed".format(_address))
    # add

    #  
    def __add_user(self, _address: str):
        ind = self.__get_free_socket()
        self.clients_logs[ind] = Log("{}.log".format(_address))
        self.clients_ip[ind] = _address
        self.incoming_requests[_address] = []
        self.log.save_data("Added user {}".format(_address))

    #       
    def __add_keys(self, _address: str, _key: rsa.key.PublicKey, _my_key: rsa.key.PrivateKey):
        ind = self.__get_ind_by_address(_address)
        try:
            self.keys[ind] = _key
            self.my_keys[ind] = _my_key
        except TypeError:
            return

    #     
    def __add_request(self, _address: str, _message: bytes):
        self.incoming_requests[_address].append(_message.decode())
        self.clients_logs[self.__get_ind_by_address(_address)].save_data("from {}: {}".format(_address, str(_message)))
        self.log.save_data("Get incoming message from {}".format(_address))

    # get

    #     
    # if self.__get_free_socket() is not None: *
    def __get_free_socket(self):
        for i in range(len(self.socket_busy)):
            if not self.socket_busy[i]:
                return i
        return None

    #   ,    
    def __get_ind_by_address(self, _address: str):
        for i in range(len(self.clients_ip)):
            if self.clients_ip[i] == _address:
                return i
        else:
            return None

    #     
    def get_request(self, _address: str):
        data = self.incoming_requests[_address][0]
        self.incoming_requests[_address] = [self.incoming_requests[_address][i]
                                            for i in range(1, len(self.incoming_requests[_address]))]
        return data

    # check

    #      
    # if self.check_request(_address): *
    def check_request(self, _address: str):
        return bool(self.incoming_requests.get(_address))

    # return True if you already connected to _address else False
    def check_address(self, _address: str):
        return True if _address in self.clients_ip else False

    # del

    #  
    def __del_user(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.clients_logs[ind].kill_log()
        self.clients_logs[ind] = Log
        self.clients_ip[ind] = ""
        self.incoming_requests.pop(_address)
        self.log.save_data("Deleted user {}".format(_address))

    #  
    def __del_key(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.keys[ind] = rsa.key.PublicKey
        self.my_keys[ind] = rsa.key.PrivateKey

    # others

    #    
    def __len__(self):
        num = 0
        for i in self.clients_ip:
            if i != "":
                num += 1
        return num

    #        
    def __bool__(self):
        for i in self.clients_ip:
            if i != "":
                return True
        return False


 

class Log:
    def __init__(self, _name: str):
        self.name = _name
        try:
            self.file = open(_name, "a")
        except FileNotFoundError:
            self.file = open(_name, "w")
        self.save_data("Log started at " + str(datetime.datetime.now()))
        self.file.close()

    #    
    def save_data(self, _data: str):
        self.file = open(self.name, "a")
        self.file.write("{}\n".format(_data))
        self.file.close()

    #       
    @staticmethod
    def read_and_return_list(_name: str):
        try:
            file = open(_name, "r")
        except FileNotFoundError:
            return []
        data = file.read()
        return data.split("\n")

    #  
    def kill_log(self):
        self.file = open(self.name, "a")
        self.save_data("Log stopped at {}\n".format(datetime.datetime.now()))
        self.file.close()


 



 



 

    def __init__(self, _port: int, _max_clients: int = 1):
        #   
        self.running = True
        #  
        self.port = _port
        #  - 
        self.max_clients = _max_clients
        #  
        self.clients_ip = ["" for i in range(self.max_clients)]
        #    
        self.incoming_requests = {}
        #  
        self.clients_logs = [Log for i in range(self.max_clients)]
        #  
        self.client_sockets = [socket.socket() for i in range(self.max_clients)]
        #  
        for i in self.client_sockets:
            i.settimeout(0.2)
        #     
        self.keys = [rsa.key.PublicKey for i in range(self.max_clients)]
        #     
        self.my_keys = [rsa.key.PrivateKey for i in range(self.max_clients)]
        #   
        self.socket_busy = [False for i in range(self.max_clients)]
        #  
        self.blacklist = ["127.0.0.1"] + Log.read_and_return_list("blacklist.txt")
        #  
        self.server_socket = socket.socket()
        #  
        self.server_socket.settimeout(0.2)
        #  
        self.server_socket.bind(('localhost', _port))
        self.server_socket.listen(self.max_clients)
        self.log = Log("server.log")
        self.log.save_data("Server initialized")


 


    def __add_user(self, _address: str):
        ind = self.__get_free_socket()
        self.clients_logs[ind] = Log("{}.log".format(_address))
        self.clients_ip[ind] = _address
        self.incoming_requests[_address] = []
        self.log.save_data("Added user {}".format(_address))


 

    def __add_keys(self, _address: str, _key: rsa.key.PublicKey, _my_key: rsa.key.PrivateKey):
        ind = self.__get_ind_by_address(_address)
        try:
            self.keys[ind] = _key
            self.my_keys[ind] = _my_key
        except TypeError:
            return


 

    def __add_request(self, _address: str, _message: bytes):
        self.incoming_requests[_address].append(_message.decode())
        self.clients_logs[self.__get_ind_by_address(_address)].save_data("from {}: {}".format(_address, str(_message)))
        self.log.save_data("Get incoming message from {}".format(_address))


 

    def __del_user(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.clients_logs[ind].kill_log()
        self.clients_logs[ind] = Log
        self.clients_ip[ind] = ""
        self.incoming_requests.pop(_address)
        self.log.save_data("Deleted user {}".format(_address))


 
    def __del_key(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.keys[ind] = rsa.key.PublicKey
        self.my_keys[ind] = rsa.key.PrivateKey


 


 


    def check_request(self, _address: str):
        return bool(self.incoming_requests.get(_address))


 
    def check_address(self, _address: str):
        return True if _address in self.clients_ip else False


 
    def __get_free_socket(self):
        for i in range(len(self.socket_busy)):
            if not self.socket_busy[i]:
                return i
        return None


    def __get_ind_by_address(self, _address: str):
        for i in range(len(self.clients_ip)):
            if self.clients_ip[i] == _address:
                return i
        else:
            return None


 
    def get_request(self, _address: str):
        data = self.incoming_requests[_address][0]
        self.incoming_requests[_address] = [self.incoming_requests[_address][i]
                                            for i in range(1, len(self.incoming_requests[_address]))]
        return data


 
    def create_session(self, _address: str):
        self.log.save_data("Creating session with {}".format(_address))
        ind = self.__get_free_socket()
        if _address in self.blacklist:
            self.log.save_data("{} in blacklist".format(_address))
            return
        if ind is None:
            self.log.save_data("All sockets are busy, can`t connect to {}".format(_address))
            return
        try:
            self.__add_user(_address)
            thread = Thread(target=self.__connect, args=(_address, 1))
            thread.start()
            thread.join(0)
            connection, address = self.server_socket.accept()
            connection.settimeout(0.2)
        except OSError:
            self.log.save_data("Failed to create session with {}".format(_address))
            self.__del_user(_address)
            return
        my_key = rsa.newkeys(512)
        self.raw_send(_address, my_key[0].save_pkcs1())
        key = connection.recv(162).decode()
        self.clients_logs[ind].save_data("from {}: {}".format(_address, key))
        key = rsa.PublicKey.load_pkcs1(key)
        self.__add_keys(_address, key, my_key[1])
        while self.running and self.socket_busy[ind]:
            try:
                data = connection.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                self.close_connection(_address)
                return
            if data:
                data = rsa.decrypt(data, self.my_keys[ind])
                self.__add_request(_address, data)
        try:
            self.close_connection(_address)
        except TypeError or KeyError:
            pass


 

    def __connect(self, _address: str, *args):
        ind = self.__get_ind_by_address(_address)
        try:
            self.client_sockets[ind].connect((_address, self.port))
            self.socket_busy[ind] = True
            return True
        except OSError:
            return False


 


    def close_connection(self, _address: str):
        ind = self.__get_ind_by_address(_address)
        self.__del_key(_address)
        self.__reload_socket(ind)
        self.__del_user(_address)


 

    def kill_server(self):
        self.running = False
        sleep(1)
        self.server_socket.close()
        self.log.kill_log()
        for i in self.client_sockets:
            i.close()
        for i in self.clients_logs:
            try:
                i.kill_log()
            except TypeError:
                pass


 


    def __reload_socket(self, _ind: int):
        self.client_sockets[_ind].close()
        self.client_sockets[_ind] = socket.socket()
        self.socket_busy[_ind] = False


 



 


    def __bool__(self):
        for i in self.clients_ip:
            if i != "":
                return True
        return False


 


    def __len__(self):
        num = 0
        for i in self.clients_ip:
            if i != "":
                num += 1
        return num


 



 


    def __init__(self, _name: str):
        self.name = _name
        try:
            self.file = open(_name, "a")
        except FileNotFoundError:
            self.file = open(_name, "w")
        self.save_data("Log started at " + str(datetime.datetime.now()))
        self.file.close()


 


    def save_data(self, _data: str):
        self.file = open(self.name, "a")
        self.file.write("{}\n".format(_data))
        self.file.close()


 



#read_and_return_list
    @staticmethod
    def read_and_return_list(_name: str):
        try:
            file = open(_name, "r")
        except FileNotFoundError:
            return []
        data = file.read()
        return data.split("\n")
