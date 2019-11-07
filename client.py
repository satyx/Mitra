import socket
from threading import Thread
import sys
import tkinter
import time
import hashlib
import getpass


def receive():
    """Handles receiving of messages."""
    while True:
        #print(4)
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            #client_socket.settimeout(None)            
            if not msg or msg=="{quit}":
                client_socket.close()
                top.quit()
                break
            elif msg == "Invalid Username":
                client_socket.close()
                top.quit()
                print("Invalid Username. Closing Connection......")
                break
                
            else:
                msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            #print(8)
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    try:
        msg = my_msg.get()
        my_msg.set("")  # Clears input field.
        client_socket.sendall(bytes(msg, "utf8"))
        if msg == "{quit}":
            #print(6)
            client_socket.close()
            top.quit()
    except KeyboardInterrupt:
        #print(2)
        print("Caught Keyboard interrupt.Exitting")
        client_socket.close()
        top.quit()
        sys.exit(1)
    except BrokenPipeError:
        print("Broken Pipe Error")
        client_socket.close()
        top.quit()
        sys.exit(1)
    

def on_closing(event=None):
    """This function is to be called when the window is closed."""
    #print(7)
    my_msg.set("{quit}")
    send()

def client_signup(client):
    while True:
        username = input("Enter Desired Username(max 20 characters):")    #Vulnerable
        if len(username)>20:
            print("Invalid Username. Please choose a username of length upto 20 characters")
        else:
            break
    while True:
        password = getpass.getpass("Choose Your Password(Upto 32 characters):")    #Vulnerable
        if len(password)>32:
            print("Invalid Username. Please choose a username of length upto 20 characters")
            continue
        re_password = getpass.getpass("Re-Enter Your Password:")
        if password == re_password:
            hashpassword = (hashlib.sha256(password.encode())).hexdigest()
            break
        else:
            print("Password Doesn't Match")
        #print(hashpassword)
    for padding_index in range(len(username),20):
        username+="#"
    try:    
        client.sendall(bytes(username,"utf-8"))

        #time.sleep(0.5)
        client.sendall(bytes(hashpassword,"utf-8"))

        status = client.recv(BUFSIZ).decode("utf-8")
        if not status:
            client.close()
            sys.exit(1)
    except ConnectionError:
        print("Connection closed. Please reconnect to the server")
        client.close()
        sys.exit(1)
    
    if status=='Y':
        return True
    else:
        return False
    
def login(client):
    #prompt = client.recv(1024).decode("utf-8")
    username = input("Username:")
    for padding_index in range(len(username),20):
        username+="#"
    client.sendall(bytes(username[:20],"utf-8"))
    password = hashlib.sha256(getpass.getpass("Password:").encode()).hexdigest()
    client.sendall(bytes(password,"utf-8"))
    status = client.recv(1).decode("utf-8")
    if status == "Y":
        return True
    else:
        return False


if __name__ == "__main__":
    
    HOST = input('Enter host: ')
    PORT = input('Enter port: ')
    #print(3)
    if not PORT:
        PORT = 33000
    else:
        PORT = int(PORT)

    BUFSIZ = 1024
    ADDR = (HOST, PORT)
    
    #----Now comes the sockets part----
    
    try:
        top = None #GUI Instance
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Note: Keeping the flag setblocking as False would lead to trigger actions on the client side
                #Even if the connection is still not established
        #client_socket.setblocking(False)        #Don't wait or "hang" for the connection to establish
        #client_socket.connect_ex(ADDR)          #sock.connect() would have immediately raised an error as sock.setblocking()
                                                # is set false
        client_socket.connect(ADDR)
        while True:
            choice = input("1. Chatroom\n2. Signup\n3. Quit\nInput:")
            if choice=="1":
                client_socket.sendall(bytes("1","utf-8"))
                if login(client_socket):
                    print("Successfully Logged In")
                    break
                else:
                    print("Invalid Username/Password")
                    continue
            elif choice=="2":
                client_socket.sendall(bytes("2","utf-8"))
                if client_signup(client_socket):
                    print("Successful Registration")
                else:
                    print("Unsuccessful Registration")
                continue
            elif choice=="3":
                client_socket.sendall(bytes("3","utf-8"))
                #trash = client_socket.recv(BUFSIZ)
                client_socket.close()
                sys.exit(1)
                #print(1)
            else:
                print("Invalid choice Entered")
                
        top = tkinter.Tk()
        top.title("Mitra")

        messages_frame = tkinter.Frame(top)
        my_msg = tkinter.StringVar()  # For the messages to be sent.
        my_msg.set("Type your messages here.")
        scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
        # Following will contain the messages.
        msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
        msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
        msg_list.pack()
        messages_frame.pack()

        entry_field = tkinter.Entry(top, textvariable=my_msg)
        entry_field.bind("<Return>", send)
        entry_field.pack()
        send_button = tkinter.Button(top, text="Send", command=send)
        send_button.pack()

        top.protocol("WM_DELETE_WINDOW", on_closing)

        receive_thread = Thread(target=receive,daemon=True)
        receive_thread.start()
        

        tkinter.mainloop()  # Starts GUI execution.
    except KeyboardInterrupt:
        #print(2)
        print("Caught Keyboard interrupt.Exitting")
        client_socket.close()
        if top:
            top.quit()
        sys.exit(1)
    except ConnectionRefusedError:
        print("The server (%s:%s) is not active. Exitting..." %ADDR)
        if top != None:
            top.quit()
        sys.exit(1)
        
