#from socket import AF_INET, socket, SOCK_STREAM
import socket
from threading import Thread
import sys
import time
import json
#userbase = ["Satyam","Rohit","Ashay","Jalaj","Shruti","Biswajit","Mansi"]
with open("userbase.json") as db:
    userbase = json.load(db)
#HOST = '10.145.233.242'
HOST = sys.argv[1]
PORT = int(sys.argv[2])
BUFSIZ = 1024
ADDR = (HOST, PORT)

clients = {}
addresses = {}

if len(sys.argv)!=3:
    print("Usage:python <filename> <host> <port>")
    sys.exit(1)

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    try:
        while True:
            #print("hello")
            client, client_address = SERVER.accept()
            print("%s:%s has connected." % client_address)
            broadcast_selective(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"),[client])
            addresses[client] = client_address
            Thread(target=handle_client, args=(client,client_address,)).start()
    except KeyboardInterrupt:
        print("Caught Keyboard Interrupt")
    finally:
        return

def authentication(client):         # Returns <credentials' validity> <Retry?> <Username(=None, when invalid)>
    broadcast_selective(bytes("Enter Your Username", "utf8"),[client])
    username = client.recv(BUFSIZ).decode("utf8")
    if not username:
        client.close()
        return False,False,None
    elif username == "{quit}":
        broadcast_selective(bytes("{quit}", "utf8"),[client])
        return False,False,None
       
    print("<%s> is attempting to login" %username)
    broadcast_selective(bytes("Enter Password","utf-8"),[client])
    password = client.recv(BUFSIZ).decode("utf8")
    if not password:
        client.close()
        return False,False,None
    elif password == "{quit}":
        broadcast_selective(bytes("{quit}", "utf8"),[client])
        return False,False,None
    
    if username not in userbase or password != userbase[username]:
        broadcast_selective(bytes("Invalid Username or Password", "utf8"),[client])
        print("<%s> Invalid Username/Password" %username)
        return False,True,None
    print("<%s> successfully logged in" %username)
    return True,False,username


def handle_client(client,client_address):  # Takes client socket as argument.
    """Handles a single client connection."""

    while True:
        valid, retry, username = authentication(client)
        if valid:
            break
        
        if not retry:
            broadcast_selective(bytes("{quit}", "utf8"),[client])
            #client.send(bytes("{quit}", "utf8"))
            print("%s:%s has disconnected." % client_address)
            client.close()
            return

    welcome = 'Welcome ! If you ever want to quit, type {quit} to exit.'
    broadcast_selective(bytes(welcome, "utf8"),[client])
    msg = "%s has joined the chat!" % username
    broadcast_global(bytes(msg, "utf8"),client_address)
    clients[client] = username

    while True:
        msg = client.recv(BUFSIZ)
        if not msg:
            broadcast_selective(bytes("{quit}", "utf8"),[client])
            client.close()
            del clients[client]
            break
        elif msg != bytes("{quit}", "utf8"):
            broadcast_global(msg,client_address, username+": ")
        else:
            broadcast_selective(bytes("{quit}", "utf8"),[client])
            print("%s:%s has disconnected." % client_address)
            client.close()
            del clients[client]
            broadcast_global(bytes("%s has left the chat." % username, "utf8"),client_address)
            break


def broadcast_global(msg,client_address=None, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    invalid_clients=[]
    for client in clients:
        try:
            client.send(bytes(prefix, "utf8")+msg)
        except BrokenPipeError:
            invalid_clients.append(client)
            continue
    for client in invalid_clients:
        print("%s:%s has disconnected." % client_address)
        client.close()
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % name, "utf8"))


def broadcast_selective(msg,client_list):
    invalid_clients=[]
    for index in range(len(client_list)):
        try:
            (client_list[index]).send(msg)
        except BrokenPipeError or OSError:
            invalid_clients.append(client_list[index])
            continue
    for client in invalid_clients:
        print("%s:%s has disconnected." % client_address)
        client.close()
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % name, "utf8"))


if __name__ == "__main__":
    try:
        SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        #To override, if the given address is already in use
        SERVER.bind(ADDR)
        SERVER.listen(5)
        print("Waiting for connection...")
        ACCEPT_THREAD = Thread(target=accept_incoming_connections,daemon=True) #Stop execution of ACCEPT_THREAD as soon as server terminates
        print("-----Enter {quit} to exit-----")
        ACCEPT_THREAD.start()
        while True:
            z = input()
            if z == "{quit}":
                print("Closing Server. Exitting....")
                SERVER.close()
                sys.exit(1)
        ACCEPT_THREAD.join()
        SERVER.close()
    except KeyboardInterrupt:
        print("Caught Keyboard Interrupt")
        for client in clients:
            client.send(bytes("*****Server Disconnected*******", "utf8"))
            client.send(bytes("{quit}", "utf8"))
            
        SERVER.close()
        sys.exit(1)
