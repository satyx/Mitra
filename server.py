import socket
from threading import Thread
import sys
import time
import json
import datetime
with open("userbase.json") as db:
    userbase = json.load(db)

if len(sys.argv)!=3:
    print("Usage:python <filename> <host> <port>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])
BUFSIZ = 1024

ADDR = (HOST, PORT)

last_client = None


#flags
invalid = 0
valid = 1
already_logged_in =2


clients = {}
addresses = {}
user_client = {}


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    try:
        while True:
            client, client_address = SERVER.accept()
            response = "%s:%s has connected." % client_address
            logging(response)
            print(response)
            addresses[client] = client_address
            Thread(target=handle_client, args=(client,client_address,)).start()
    except KeyboardInterrupt:
        response = "Caught Keyboard Interrupt while accepting connections"
        logging(response)
        print(response)
    finally:
        return


def authentication(client,client_address):         # Returns <credentials' validity> <Connected> <Username(=None, when invalid)>
    #broadcast_selective(bytes("Enter Your Username", "utf8"),[client])
    try:

        username_length = int(client.recv(4).decode("utf8"))
        logging("<LOGIN>:Username size received")
        username = client.recv(username_length).decode("utf8")
        logging("<LOGIN>:Username received")
        #for index in range(len(username)):
        #    if username[index]=="#":
        #        username = username[:index]
        #        break
        password_length = int(client.recv(4).decode("utf8"))    #Password length is fixed(=64, hashed string) but to maintain uniformity we are accepting it's length
        logging("<LOGIN>:Password size received")
        password = client.recv(password_length).decode("utf8")
        logging("<LOGIN>:Password received")
        if not username:
            logging("<LOGIN>:Invalid Username <%s>. Authetication Failed!"%(username))
            client.close()
            return invalid,True,None
        elif username == "<QUIT>":
            logging("<LOGIN>:Invalid Username <%s>. Authetication Failed!"%(username))
            broadcast_selective(bytes("N", "utf8"),[client],system=True)
            return invalid,True,None
        
        response = "<LOGIN>:<%s> is attempting to login" %username
        logging(response)
        print(response)
        #broadcast_selective(bytes("Enter Password","utf-8"),[client])
        if not password:
            logging("<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!"%(username))
            client.close()
            return invalid,True,None
        elif password == "<QUIT>":
            logging("<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!"%(username))
            broadcast_selective(bytes("N", "utf8"),[client],system=True)
            return invalid,True,None
        
        if username not in userbase or password != userbase[username]:
            response = "<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!"%(username)
            logging(response)
            broadcast_selective(bytes("N", "utf8"),[client],system=True)
            print(response)
            return invalid,True,None
        
        if username in user_client:
            response = "<LOGIN>:Attempt for multiple login for user <"+username+"> from client address (%s:%s). Authentication Failed!"%(client_address)
            logging(response)
            print(response)
            broadcast_selective(bytes("N", "utf8"),[client],system=True)
            return already_logged_in,True,None

        #Logging for successful authentification at caller function
        return valid, True, username
    except OSError:
        response = "<LOGIN>:OSError Caught at <%s:%s>" %(client_address)
        logging(response)
        return None, False, None


def client_signup(client,client_address):              #Vulnerable. Returns userID,status,connection
    global userbase
    try:
        username_length = int(client.recv(4).decode("utf-8"))
        logging("<SIGNUP>:Username size received")
        username = client.recv(username_length).decode("utf-8")
        logging("<SIGNUP>:Username received")

        password_length = int(client.recv(4).decode("utf-8"))
        logging("<SIGNUP>:Password size received")
        password = client.recv(password_length).decode("utf-8")
        logging("<SIGNUP>:Password received")
    except:
        response = "<SIGNUP>:SignUp Exception Raised at <%s:%s>" %(client_address)
        logging(response)
        print(response)
        return None,False,False

    if username in userbase:
        response = "<SIGNUP>:Username unavailable"
        logging(response)
        return username,False,True
    else:
        userbase[username] = password
        with open("userbase.json","w") as db:
            json.dump(userbase,db)
        #logging done by caller    
        return username,True,True


def handle_client(client,client_address):  # Takes client socket as argument.
    """Handles a single client connection."""
    global last_client,clients,user_client

    try:
        while True:
            choice_length = int(client.recv(4).decode("utf-8"))
            logging("<QUERY>:query length received")
            choice = client.recv(choice_length).decode("utf-8")
            logging("<QUERY>:query received")
                        
            if choice=="1":
                response = "<QUERY>:Login Request by <%s:%s>" %client_address
                logging(response)
                print(response)
                status, connected, username = authentication(client,client_address)
                if not connected:
                    response = "%s:%s has disconnected." % client_address
                    logging(response)
                    print(response)
                    last_client = None
                    client.close()
                    return
                if status == valid:
                    response = "<LOGIN>:<%s> successfully logged in" %username
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("Y","utf-8"),[client],system=True)
                    break

            elif choice=="2":
                response = "<QUERY>:<%s:%s> requesting user sign-up" %client_address
                logging(response)
                print(response)
                userID,status,connected = client_signup(client,client_address)
                if not connected:
                    response = "%s:%s has disconnected." % client_address
                    logging(response)
                    print(response)
                    last_client = None
                    client.close()
                    return
                if status:
                    response = "User <"+userID+"> has been registered from <"+str(client_address)+">"
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("Y","utf-8"),[client],system=True)
                else:
                    response = "User <"+userID+"> has been NOT BEEN registered from <"+str(client_address)+">"
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("N","utf-8"),[client],system=True)

            elif choice=="3":
                response = "<QUERY>:%s:%s has disconnected." % client_address
                logging(response)
                print(response)
                last_client = None
                client.close()
                return

            else:
                response = "<QUERY>:Invalid Query Requested. Closing Connection by <%s:%s>" %(client_address)
                logging(response)
                print(response)
                broadcast_selective(bytes("<QUIT>", "utf8"),[client])
                #client.sendall(bytes("<QUIT>", "utf8"))
                last_client = None
                client.close()
                return
    except OSError:
        response = "OSError Caught due to <%s:%s>" %(client_address)
        logging(response)
        response = "%s:%s has disconnected." % client_address
        logging(response)
        print(response)
        last_client = None
        client.close()
        return
    
    clients[client] = username
    user_client[username] = client
    update_upon_login(client)
    welcome = '****Welcome ! If you ever want to quit, type <QUIT> to Exit****'
    broadcast_selective(bytes(welcome, "utf8"),[client],system=True)
    msg = "%s has joined the chat!" % username
    broadcast_global(bytes(msg, "utf8"),client_address,system=True)
    

    while True:
        msg = ""
        while True:
            size = int(client.recv(4).decode("utf-8"))
            if not size:
                broadcast_selective(bytes("<QUIT>", "utf8"),[client],system=True)
                client.close()
                del user_client[clients[client]]
                del clients[client]
                return
            msg_sliced = client.recv(size).decode("utf-8")
            if not msg_sliced:
                broadcast_selective(bytes("<QUIT>", "utf8"),[client],system=True)
                client.close()
                del user_client[clients[client]]
                del clients[client]
                return
            
            if size==5 and msg_sliced=="<END>" and msg_sliced[:7] != "<START>":
                break
            msg+=msg_sliced[7:]
        msg = bytes(msg,"utf-8")
        
        if msg != bytes("<QUIT>", "utf8"):
            broadcast_global(msg,client_address, "["+username+"]: ")
        else:
            broadcast_selective(bytes("<QUIT>", "utf8"),[client],system=True)
            last_client = None
            client.close()
            print("<%s> successfully logged out" %(clients[client]))
            print("%s:%s has disconnected." % client_address)
            del user_client[clients[client]]
            del clients[client]
            broadcast_global(bytes("%s has left the chat." % username, "utf8"),client_address,system=True)
            break
        

def broadcast_global(raw_msg,client_address=None, prefix="",system=False):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    raw_msg = raw_msg.decode("utf-8")  #Temporary

    global last_client,clients,user_client
    invalid_clients={}

    if last_client !=prefix:
        raw_msg = prefix+raw_msg
    
    if raw_msg!="<QUIT>":
        with open("chat_backup.txt","a") as chatfile:
            if system:
                logging("<BROADCAST> By Server")
                chatfile.write("<0000>"+raw_msg+"\n") #0000 corresponds to system's message
            else:
                logging("<BROADCAST> By User")
                chatfile.write("<0001>"+raw_msg+"\n")   #0001 corresponds to system's message


    for client in clients:
        try:
            if system:
                msg = "<SYSTEM>" + raw_msg
                msg = ("%04d" %len(msg))+msg
                client.sendall(bytes(msg, "utf8"))
            else:
                for index in range(0,len(raw_msg),1024):
                    msg_slice = raw_msg[index:index+1024]
                    msg_slice = "<START>" + msg_slice
                    msg_slice = ("%04d" %len(msg_slice))+msg_slice
                    client.sendall(bytes(msg_slice, "utf8"))
                client.sendall(bytes("0005<END>", "utf8"))

        except BrokenPipeError:
            response = "BrokenPipeError Caught during Broadcasting Globally"
            logging(response)
            print(response)
            invalid_clients[client] = clients[client] 
            continue
    for client in invalid_clients:
        #response = "%s:%s has disconnected." %client_address
        #logging(response)
        #print(response)
        last_client = None
        client.close()

        response = "<%s> successfully logged out" %(clients[client])
        logging(response)
        print(response)

        response = "%s:%s has disconnected." %client_address
        logging(response)
        print(response)            
        del user_client[clients[client]]
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % invalid_clients[client], "utf8"),system=True)
    last_client = prefix


def broadcast_selective(raw_msg,client_list,system=False):
    global last_client,clients,user_client
    raw_msg = raw_msg.decode("utf-8")   #Temporary
    invalid_clients={}
    for index in range(len(client_list)):
        try:
            if system:
                logging("<BROADCAST> Broadcasting Selectively")
                msg = "<SYSTEM>"+raw_msg
                msg = ("%04d" %len(msg))+msg
                (client_list[index]).sendall(bytes(msg,"utf-8"))
            else:
                (client_list[index]).sendall(bytes(raw_msg,"utf-8"))
        except BrokenPipeError:
            response = "BrokenPipeError Caught during Broadcasting Selectively"
            logging(response)
            print(response)
            invalid_clients.append(client_list[index])
            continue
        except OSError:
            response = "OSError Caught during Broadcasting Globally"
            logging(response)
            print(response)
            invalid_clients[client] = clients[client]
            continue
    for client in invalid_clients:
        last_client = None
        client.close()
        response = "<%s> successfully logged out" %(clients[client])
        logging(response)
        print(response)
        
        response = "%s:%s has disconnected." %client_address
        logging(response)
        print(response)

        del user_client[clients[client]]
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % invalid_clients[client], "utf8"))


def update_upon_login(client):
    response = "Loading Chats for <%s>" %(clients[client])
    logging(response)
    with open(r"chat_backup.txt","r") as chat_backup:
        lines = chat_backup.read().splitlines()   #For safety max. number of bytes are mentioned
        for line in lines:
            modified_line = "<SYSTEM>"+line[6:]
            modified_line = ("%04d" %len(modified_line))+modified_line
            client.sendall(bytes(modified_line,"utf-8"))
    return

def logging(msg):
    date = (str(datetime.date.today())).replace("-","_")
    try:
        logfile = open("logfiles/log_"+date+".txt","a")
    except:
        os.makedirs("logfiles")
        logfile = open("logfiles/log_"+date+".txt","a")
    timestamp = str(datetime.datetime.now().time())
    logfile.write("["+timestamp+"]:"+msg+"\n")
    logfile.close()


if __name__ == "__main__":
    try:
        SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        #To override, if the given address is already in use
        SERVER.bind(ADDR)
        SERVER.listen(5)
        print("Waiting for connection...")
        ACCEPT_THREAD = Thread(target=accept_incoming_connections,daemon=True) #Stop execution of ACCEPT_THREAD as soon as server terminates
        print("-----Enter <QUIT> to exit-----")
        ACCEPT_THREAD.start()
        while True:
            z = input()
            logging("<INPUT>:"+z)
            if z == "<QUIT>":
                response = "<SYSTEM>:Closing Server. Aborting!"
                logging(response)
                print("<SYSTEM>:Closing Server. Aborting!")
                broadcast_global(bytes("<QUIT>","utf-8"),system=True)
                SERVER.close()
                sys.exit(1)
            elif z == "<ACTIVE USERS>":
                response = "<SYSTEM>:"+repr(list(user_client.keys()))
                logging(response)
                print(response)
            elif z == "<DELETE CHAT BACKUP>":
                if len(user_client)==0:
                    open("chat_backup.txt","w").close()
                    response = "<SYSTEM>:Data Cleared Successfully"
                    logging(response)
                    print("<SYSTEM>:Data Cleared Successfully")
                else:
                    response="<SYSTEM>:Chatroom Currently Active"
                    logging(response)
                    print("<SYSTEM>:Chatroom Currently Active")
            else:
                response = "<SYSTEM>:Unknown Command"
                logging(response)
                print(response)
        ACCEPT_THREAD.join()
        SERVER.close()
    except KeyboardInterrupt:
        response = "<SYSTEM>:Caught Keyboard Interrupt"
        logging(response)
        print(response)
        for client in clients:
            response = "*****Server Disconnected*****"
            logging(response)
            server_disconnect = bytes("*****Server Disconnected*****","utf-8")
            broadcast_global(server_disconnect)
            #client.sendall(bytes("*****Server Disconnected*****", "utf8"))
            broadcast_global(bytes("<QUIT>", "utf8"),system=True)
            #client.sendall(bytes("<QUIT>", "utf8"))
            
        SERVER.close()
        sys.exit(1)
