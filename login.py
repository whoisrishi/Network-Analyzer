import tkinter
import subprocess,os
import customtkinter
from PIL import ImageTk,Image

customtkinter.set_appearance_mode("dark")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("green")  # Themes: blue (default), dark-blue, green

app = customtkinter.CTk() 
app.geometry("600x440")
app.title('Login')

img1=ImageTk.PhotoImage(Image.open("./assets/pattern1.jpg"))
l1=customtkinter.CTkLabel(master=app,image=img1)
l1.pack()

def login_page():

    def network_analyzer():

        name=username.get()
        passcode=password.get()
        main_username="Admin"
        main_password="Passcode"

        if main_username == name :
            if main_password == passcode :
                print("Login successful!")
                if os.path.exists("main_features.py"):
                    subprocess.Popen(["python", "main_features.py"])
                    app.destroy()
                    
                else:
                    print("Error: File main_features.py not found.")
            else:
                print("Invalid password.")
        else:
            print("Invalid username.")

    login_frame=customtkinter.CTkFrame(master=l1, width=320, height=360, corner_radius=15)

    l2=customtkinter.CTkLabel(master=login_frame, text="Log into your Account",font=('Century Gothic',20))
    l2.place(x=50, y=45)

    username=customtkinter.CTkEntry(master=login_frame, width=220, placeholder_text='Admin')
    username.place(x=50, y=110)

    password=customtkinter.CTkEntry(master=login_frame, width=220, placeholder_text='Pass@123', show="*")
    password.place(x=50, y=165)

    l3=customtkinter.CTkLabel(master=login_frame, text="Forget password?",font=('Century Gothic',12))
    l3.place(x=155,y=195)

    log_bt = customtkinter.CTkButton(master=login_frame, width=220, text="Login", command=network_analyzer, corner_radius=6)
    log_bt.place(x=50, y=240)

    button2= customtkinter.CTkButton(master=login_frame, width=100, text="Sign_Up", command=signup_page, corner_radius=6, fg_color='white', text_color='black', hover_color='#AFAFAF')
    button2.place(x=50, y=290)

    button3= customtkinter.CTkButton(master=login_frame, width=100, text="Refresh", command=signup_page, corner_radius=6, fg_color='white', text_color='black', hover_color='#AFAFAF')
    button3.place(x=170, y=290)

    login_frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)


def signup_page():

    signup_frame=customtkinter.CTkFrame(master=l1, width=320, height=360, corner_radius=15)

    l4=customtkinter.CTkLabel(master=signup_frame, text="Welcome to our service",font=('Century Gothic',20))
    l4.place(x=50, y=45)

    new_user=customtkinter.CTkEntry(master=signup_frame, width=220, placeholder_text='Username')
    new_user.place(x=50, y=110)

    new_pass=customtkinter.CTkEntry(master=signup_frame, width=220, placeholder_text='Password', show="*")
    new_pass.place(x=50, y=165) 

    l5=customtkinter.CTkLabel(master=signup_frame, text="Forget password?",font=('Century Gothic',12))
    l5.place(x=155,y=195)

    sign_bt = customtkinter.CTkButton(master=signup_frame, width=220, text="Sign_Up", command=login_page, corner_radius=6)
    sign_bt.place(x=50, y=240)

    button4= customtkinter.CTkButton(master=signup_frame, width=100, text="Login", command=login_page, corner_radius=6, fg_color='white', text_color='black', hover_color='#AFAFAF')
    button4.place(x=50, y=290)

    button5= customtkinter.CTkButton(master=signup_frame, width=100, text="Refresh", command=login_page, corner_radius=6, fg_color='white', text_color='black', hover_color='#AFAFAF')
    button5.place(x=170, y=290)

    signup_frame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

login_page()

app.mainloop()