import socket
from threading import Thread
import sys
import time
import json
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

clients = {}
addresses = {}


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    try:
        while True:
            client, client_address = SERVER.accept()
            print("%s:%s has connected." % client_address)
            addresses[client] = client_address
            Thread(target=handle_client, args=(client,client_address,)).start()
    except KeyboardInterrupt:
        print("Caught Keyboard Interrupt")
    finally:
        return


def authentication(client):         # Returns <credentials' validity> <Connected> <Username(=None, when invalid)>
    #broadcast_selective(bytes("Enter Your Username", "utf8"),[client])
    try:

        username_length = int(client.recv(4).decode("utf8"))
        username = client.recv(username_length).decode("utf8")
        #for index in range(len(username)):
        #    if username[index]=="#":
        #        username = username[:index]
        #        break
        password_length = int(client.recv(4).decode("utf8"))    #Password length is fixed(=64, hashed string) but to maintain uniformity we are accepting it's length
        password = client.recv(password_length).decode("utf8")
        if not username:
            client.close()
            return False,True,None
        elif username == "<QUIT>":
            broadcast_selective(bytes("N", "utf8"),[client])
            return False,True,None
           
        print("<%s> is attempting to login" %username)
        #broadcast_selective(bytes("Enter Password","utf-8"),[client])
        if not password:
            client.close()
            return False,True,None
        elif password == "<QUIT>":
            broadcast_selective(bytes("N", "utf8"),[client])
            return False,True,None
        
        if username not in userbase or password != userbase[username]:
            broadcast_selective(bytes("N", "utf8"),[client])
            print("<%s> Invalid Username/Password" %username)
            return False,True,None
        print("<%s> successfully logged in" %username)
        return True, True, username
    except OSError:
        return None, False, None


def client_signup(client):              #Vulnerable. Returns userID,status,connection
    global userbase
    try:
        username_length = int(client.recv(4).decode("utf-8"))
        username = client.recv(username_length).decode("utf-8")
        
        password_length = int(client.recv(4).decode("utf-8"))
        password = client.recv(password_length).decode("utf-8")
    except:
        print("SignUp Exception Raised")
        return None,False,False

    if userID in userbase:
        return userID,False,True
    else:
        userbase[userID] = password
        with open("userbase.json","w") as db:
            json.dump(userbase,db)
        return userID,True,True


def handle_client(client,client_address):  # Takes client socket as argument.
    """Handles a single client connection."""
    global last_client,clients

    try:
        while True:
            choice_length = int(client.recv(4).decode("utf-8"))
            choice = client.recv(choice_length).decode("utf-8")
            if not choice:
                broadcast_selective(bytes("<QUIT>", "utf8"),[client])
                #client.sendall(bytes("<QUIT>", "utf8"))
                print("%s:%s has disconnected." % client_address)
                last_client = None
                client.close()
                return
            
            if choice=="1":
                valid, connected, username = authentication(client)
                if not connected:
                    print("%s:%s has disconnected." % client_address)
                    last_client = None
                    client.close()
                    return
                if valid:
                    broadcast_selective(bytes("Y","utf-8"),[client])
                    break

            if choice=="2":
                print("<%s> requesting user sign-up" %str(client_address))
                userID,status,connected = client_signup(client)
                if not connected:
                    print("%s:%s has disconnected." % client_address)
                    last_client = None
                    client.close()
                    return
                if status:
                    print("User <"+userID+"> has been registered from <"+str(client_address)+">")
                    broadcast_selective(bytes("Y","utf-8"),[client])
                else:
                    print("User <"+userID+"> has been NOT BEEN registered from <"+str(client_address)+">")
                    broadcast_selective(bytes("N","utf-8"),[client])

            if choice=="3":
                print("%s:%s has disconnected." % client_address)
                last_client = None
                client.close()
                return            
    except OSError:
        print("%s:%s has disconnected." % client_address)
        last_client = None
        client.close()
        return

    welcome = 'Welcome ! If you ever want to quit, type <QUIT> to exit.'
    broadcast_selective(bytes(welcome, "utf8"),[client])
    msg = "%s has joined the chat!" % username
    broadcast_global(bytes(msg, "utf8"),client_address)
    clients[client] = username

    while True:
        msg = ""
        while True:
            size = int(client.recv(4).decode("utf-8"))
            if not size:
                broadcast_selective(bytes("<QUIT>", "utf8"),[client])
                client.close()
                del clients[client]
                return
            msg_sliced = client.recv(size).decode("utf-8")
            if not msg_sliced:
                broadcast_selective(bytes("<QUIT>", "utf8"),[client])
                client.close()
                del clients[client]
                return
            
            if size==5 and msg_sliced=="<END>" and msg_sliced[:7] != "<START>":
                break
            msg+=msg_sliced[7:]
        msg = bytes(msg,"utf-8")
        
        if msg != bytes("<QUIT>", "utf8"):
            broadcast_global(msg,client_address, username+": ")
        else:
            broadcast_selective(bytes("<QUIT>", "utf8"),[client])
            print("%s:%s has disconnected." % client_address)
            last_client = None
            client.close()
            del clients[client]
            broadcast_global(bytes("%s has left the chat." % username, "utf8"),client_address)
            break
        

def broadcast_global(msg,client_address=None, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    global last_client,clients
    invalid_clients={}

    for client in clients:
        try:
            if last_client !=prefix:
                client.sendall(bytes(prefix, "utf8")+msg)
            else:
                client.sendall(msg)
        except BrokenPipeError:
            invalid_clients[client] = clients[client] 
            continue
    for client in invalid_clients:
        print("%s:%s has disconnected." % client_address)
        last_client = None
        client.close()
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % invalid_clients[client], "utf8"))
    last_client = prefix


def broadcast_selective(msg,client_list):
    global last_client,clients
    invalid_clients={}
    for index in range(len(client_list)):
        try:
            (client_list[index]).sendall(msg)
        except BrokenPipeError:
            invalid_clients.append(client_list[index])
            continue
        except OSError:
            invalid_clients[client] = clients[client]
            continue
    for client in invalid_clients:
        print("%s has disconnected." %client)
        last_client = None
        client.close()
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % invalid_clients[client], "utf8"))


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
            if z == "<QUIT>":
                print("Closing Server. Exitting....")
                SERVER.close()
                sys.exit(1)
            else:
                print("<System Message>:Unknown Command")
        ACCEPT_THREAD.join()
        SERVER.close()
    except KeyboardInterrupt:
        print("Caught Keyboard Interrupt")
        for client in clients:
            client.sendall(bytes("*****Server Disconnected*******", "utf8"))
            client.sendall(bytes("<QUIT>", "utf8"))
            
        SERVER.close()
        sys.exit(1)
