import tkinter


def create_frame(start_frame, register_frame, login_frame):
    def register():
        register_frame.tkraise()

    def login():
        login_frame.tkraise()

    start_frame.columnconfigure(0, weight=1)
    start_frame.columnconfigure(1, weight=1)
    start_frame.rowconfigure(1, weight=1)
    start_frame.rowconfigure(2, weight=1)

    label = tkinter.Label(start_frame, text="Welcome to sendme!", font="arial 20 bold")
    label.grid(row=0, column=0, columnspan=2, sticky="NEWS", pady=20)

    register_text = tkinter.Label(start_frame, text="new to sendme?", font=20)
    register_text.grid(row=1, column=0, sticky="NEWS")
    tkinter.Button(start_frame, text="register", font=20, command=register).grid(row=2, column=0)

    login_text = tkinter.Label(start_frame, text="have an existing user?", font=20)
    login_text.grid(row=1, column=1, sticky="NEWS")
    tkinter.Button(start_frame, text="log in", font=20, command=login).grid(row=2, column=1)
