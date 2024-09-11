import customtkinter

root = customtkinter.CTk()
root.title("hii")
root.geometry("300x500")

entry1 = customtkinter.CTkEntry(master=root,width=100,height=200)
entry1.pack()


def printer():
    str=entry1.get()
    print(str)

btn = customtkinter.CTkButton(master=root, width=100,height=100, text="press",command= printer )
btn.pack()

root.mainloop()