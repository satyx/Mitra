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
USERNAME_SIZ = 20
PASSWORD_SIZ = 64
ADDR = (HOST, PORT)

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
        username = client.recv(USERNAME_SIZ).decode("utf8")
        for index in range(len(username)):
            if username[index]=="#":
                username = username[:index]
                break
        time.sleep(0.5)
        password = client.recv(PASSWORD_SIZ).decode("utf8")
        if not username:
            client.close()
            return False,True,None
        elif username == "{quit}":
            broadcast_selective(bytes("N", "utf8"),[client])
            return False,True,None
           
        print("<%s> is attempting to login" %username)
        #broadcast_selective(bytes("Enter Password","utf-8"),[client])
        if not password:
            client.close()
            return False,True,None
        elif password == "{quit}":
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
    try:
        userID = client.recv(USERNAME_SIZ).decode("utf-8")
    except:
        return None,False,False
    for index in range(20):
        if userID[index]=='#':
            userID = userID[:index]
            break
    
    password = client.recv(BUFSIZ).decode("utf-8")
    if userID in userbase:
        return userID,False,True
    else:
        userbase[userID] = password
        with open("userbase.json","w") as db:
            json.dump(userbase,db)
        return userID,True,True

def handle_client(client,client_address):  # Takes client socket as argument.
    """Handles a single client connection."""

    try:
        while True:
            ch = client.recv(BUFSIZ).decode("utf-8")
            if not ch:
                broadcast_selective(bytes("{quit}", "utf8"),[client])
                #client.sendall(bytes("{quit}", "utf8"))
                print("%s:%s has disconnected." % client_address)
                client.close()
                return
            if ch=='2':
                print("<%s> requesting user sign-up" %str(client_address))
                userID,status,connected = client_signup(client)
                if not connected:
                    print("%s:%s has disconnected." % client_address)
                    client.close()
                    return
                if status:
                    print("User <"+userID+"> has been registered from <"+str(client_address)+">")
                    broadcast_selective(bytes("Y","utf-8"),[client])
                else:
                    print("User <"+userID+"> has been NOT BEEN registered from <"+str(client_address)+">")
                    broadcast_selective(bytes("N","utf-8"),[client])
            if ch=='1':
                valid, connected, username = authentication(client)
                if not connected:
                    print("%s:%s has disconnected." % client_address)
                    client.close()
                    return
                if valid:
                    broadcast_selective(bytes("Y","utf-8"),[client])
                    break
                
            if ch=='3':
                print("%s:%s has disconnected." % client_address)
                client.close()
                return            
    except OSError:
        print("%s:%s has disconnected." % client_address)
        client.close()
        return
    broadcast_selective(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"),[client])
   # while True:
        
        
        
   #"""     else:
   #         broadcast_selective(bytes("{quit}", "utf8"),[client])
   #         #client.sendall(bytes("{quit}", "utf8"))
   #         print("%s:%s has disconnected." % client_address)
   #         client.close()
   #         return"""

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
            client.sendall(bytes(prefix, "utf8")+msg)
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
            (client_list[index]).sendall(msg)
        except BrokenPipeError or OSError:
            invalid_clients.append(client_list[index])
            continue
    for client in invalid_clients:
        print("%s has disconnected." %client)
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
            else:
                print("<System Message>:Unknown Command")
        ACCEPT_THREAD.join()
        SERVER.close()
    except KeyboardInterrupt:
        print("Caught Keyboard Interrupt")
        for client in clients:
            client.sendall(bytes("*****Server Disconnected*******", "utf8"))
            client.sendall(bytes("{quit}", "utf8"))
            
        SERVER.close()
        sys.exit(1)
