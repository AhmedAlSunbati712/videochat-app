import tkinter as tk
from tkinter import messagebox
from dataclasses import dataclass
import ast
import os

from ChatClient import ChatClient


INCOMING_CALL_ASCII = [
    "▄▄ ▄▄  ▄▄  ▄▄▄▄  ▄▄▄  ▄▄   ▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄ ",
    "██ ███▄██ ██▀▀▀ ██▀██ ██▀▄▀██ ██ ███▄██ ██ ▄▄ ",
    "██ ██ ▀██ ▀████ ▀███▀ ██   ██ ██ ██ ▀██ ▀███▀ ",
    "             ▄▄▄▄  ▄▄▄  ▄▄    ▄▄              ",
    "            ██▀▀▀ ██▀██ ██    ██              ",
    "            ▀████ ██▀██ ██▄▄▄ ██▄▄▄           ",
]

CONTACTS_FILE = "contacts.txt"
MONO_FONT = ("Courier", 12)
VIDEO_SURFACE_WIDTH = 640
VIDEO_SURFACE_HEIGHT = 360


@dataclass
class Contact:
    name: str
    ip_address: str
    mac_address: str


def load_contacts():
    contacts = []
    if not os.path.exists(CONTACTS_FILE):
        return contacts
    with open(CONTACTS_FILE, "r") as f:
        for line in f:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) == 3:
                name, ip, mac = parts
                contacts.append(Contact(name, ip, mac))
    return contacts

def search_contact_by_mac(mac_address: str):
    contacts = load_contacts()
    for contact in contacts:
        if contact.mac_address == mac_address:
            return contact
    return None


def search_contact_by_ip(ip_address: str):
    contacts = load_contacts()
    for contact in contacts:
        if contact.ip_address == ip_address:
            return contact
    return None


def append_contact(contact: Contact):
    with open(CONTACTS_FILE, "a") as f:
        f.write(f"{contact.name},{contact.ip_address},{contact.mac_address}\n")


def make_app():
    root = tk.Tk()
    root.title("Video Call App")
    root.geometry("800x400")

    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)

    current_outgoing_contact = None
    incoming_call_contact = None
    active_call_contact = None
    video_photo = None
    chat_client = None

    # ----- Frames (screens) -----
    home_frame = tk.Frame(root)
    contacts_frame = tk.Frame(root)
    add_contact_frame = tk.Frame(root)
    incoming_frame = tk.Frame(root)
    initiate_frame = tk.Frame(root)  # New frame for initiating calls
    call_frame = tk.Frame(root)

    for frame in (home_frame, contacts_frame, add_contact_frame, incoming_frame, initiate_frame, call_frame):
        frame.grid(row=0, column=0, sticky="nsew")




    def set_chat_client(client: ChatClient):
        nonlocal chat_client
        chat_client = client

    def logic_callback(msg: str):
        """
        This is called from the network thread.
        It MUST NOT touch Tk directly.
        """
        # root.after(0, handle_message_on_main_thread, msg)


        print(msg)

        if msg.startswith("incoming call,"):
            _, addr = msg.split(",", 1)
            contact = None
            try:
                peer_addr = ast.literal_eval(addr.strip())
                if isinstance(peer_addr, tuple) and len(peer_addr) == 2:
                    ip, port = peer_addr
                    contact = search_contact_by_ip(ip)
                    if contact is None:
                        contact = Contact(name=f"Unknown ({ip})", ip_address=ip, mac_address="Unknown")
            except (SyntaxError, ValueError):
                pass

            if contact is not None:
                root.after(0, lambda c=contact: show_incoming_call(c))

        elif msg == "hello_ack_received":
            # The initiator received HELLO_ACK, simulate the answer
            root.after(0, lambda: simulate_answer())

        elif msg.startswith("image"):
            # Video frame received
            _, image = msg.split(",", 1)
            # Convert the image data back to PhotoImage
            photo = tk.PhotoImage(data=image)
            root.after(0, lambda p=photo: update_video_surface(p))

        




    # ---------- Helper to switch screens ----------
    def show_frame(frame):
        frame.tkraise()

    # ========== HOME SCREEN ==========
    tk.Label(home_frame, text="Welcome to Video Call App!",
             font=("Arial", 16, "bold")).pack(pady=10, anchor="w", padx=10)

    tk.Label(home_frame, text="Press the buttons below to navigate.",
             anchor="w").pack(pady=2, anchor="w", padx=10)

    status_label = tk.Label(home_frame,
                            text="Currently listening for calls *",
                            anchor="w")
    status_label.pack(pady=2, anchor="w", padx=10)

    def on_initiate_call():
        contacts = load_contacts()
        if not contacts:
            messagebox.showinfo("No contacts", "No contacts available. Add a contact first.")
            return

        if len(contacts) == 1:
            show_initiate_call(contacts[0])
            return

        # Multiple contacts: present a chooser dialog
        chooser = tk.Toplevel(root)
        chooser.title("Select Contact to Call")
        chooser.geometry("480x320")
        chooser.transient(root)
        chooser.grab_set()
        tk.Label(chooser, text="Select contact to initiate call:", anchor="w").pack(
            padx=10, pady=(10, 0), fill="x"
        )

        listbox = tk.Listbox(chooser, width=80)
        listbox.pack(padx=10, pady=8, fill="both", expand=True)
        for c in contacts:
            listbox.insert(tk.END, f"{c.name} (IP: {c.ip_address}, MAC: {c.mac_address})")

        def do_call():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("No selection", "Please select a contact to call.")
                return
            contact = contacts[sel[0]]
            chooser.destroy()
            show_initiate_call(contact)

        def do_cancel():
            chooser.destroy()

        btn_frame = tk.Frame(chooser)
        btn_frame.pack(pady=8)
        tk.Button(btn_frame, text="Call", command=do_call).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Cancel", command=do_cancel).pack(side="left", padx=6)

        # Focus the dialog
        chooser.focus_set()




    btn_initiate = tk.Button(home_frame, text="Initiate call",
                             command=on_initiate_call)
    btn_contacts = tk.Button(home_frame, text="View Contacts",
                             command=lambda: (update_contacts_list(), show_frame(contacts_frame)))
    btn_quit = tk.Button(home_frame, text="Quit", command=root.destroy)

    btn_initiate.pack(pady=5, anchor="w", padx=10)
    btn_contacts.pack(pady=5, anchor="w", padx=10)
    btn_quit.pack(pady=5, anchor="w", padx=10)

    # ========== CONTACTS SCREEN ==========
    tk.Label(contacts_frame, text="Contacts",
             font=("Arial", 14, "bold")).pack(pady=10, anchor="w", padx=10)

    contacts_listbox = tk.Listbox(contacts_frame, width=80)
    contacts_listbox.pack(pady=5, padx=10, fill="both", expand=True)

    no_contacts_label = tk.Label(contacts_frame,
                                 text="No contacts found. Press 'Add Contact' to create one.",
                                 fg="gray")

    def update_contacts_list():
        contacts_listbox.delete(0, tk.END)
        contacts = load_contacts()
        if not contacts:
            no_contacts_label.pack(pady=5, padx=10, anchor="w")
        else:
            if no_contacts_label.winfo_ismapped():
                no_contacts_label.pack_forget()
            for idx, c in enumerate(contacts, start=1):
                contacts_listbox.insert(
                    tk.END,
                    f"{idx}. {c.name} (IP: {c.ip_address}, MAC: {c.mac_address})"
                )

    btn_add_contact = tk.Button(contacts_frame, text="Add Contact",
                                command=lambda: show_frame(add_contact_frame))
    btn_back_home_from_contacts = tk.Button(contacts_frame, text="Back to Home",
                                            command=lambda: show_frame(home_frame))

    btn_add_contact.pack(pady=5, anchor="w", padx=10)
    btn_back_home_from_contacts.pack(pady=5, anchor="w", padx=10)

    # ========== ADD CONTACT SCREEN ==========
    tk.Label(add_contact_frame, text="Add New Contact",
             font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2,
                                              pady=10, padx=10, sticky="w")

    tk.Label(add_contact_frame, text="Leave Name blank or type 'b' to cancel.",
             fg="gray").grid(row=1, column=0, columnspan=2,
                             pady=2, padx=10, sticky="w")

    tk.Label(add_contact_frame, text="Name:").grid(row=2, column=0,
                                                   sticky="e", pady=5, padx=10)
    tk.Label(add_contact_frame, text="IP Address:").grid(row=3, column=0,
                                                         sticky="e", pady=5, padx=10)
    tk.Label(add_contact_frame, text="MAC Address:").grid(row=4, column=0,
                                                          sticky="e", pady=5, padx=10)

    name_entry = tk.Entry(add_contact_frame, width=40)
    ip_entry = tk.Entry(add_contact_frame, width=40)
    mac_entry = tk.Entry(add_contact_frame, width=40)

    name_entry.grid(row=2, column=1, sticky="w", pady=5)
    ip_entry.grid(row=3, column=1, sticky="w", pady=5)
    mac_entry.grid(row=4, column=1, sticky="w", pady=5)

    def clear_add_contact_form():
        name_entry.delete(0, tk.END)
        ip_entry.delete(0, tk.END)
        mac_entry.delete(0, tk.END)

    def submit_contact():
        name = name_entry.get().strip()
        ip = ip_entry.get().strip()
        mac = mac_entry.get().strip()

        if not name or name.lower() == "b":
            # cancel and go back to contacts
            clear_add_contact_form()
            update_contacts_list()
            show_frame(contacts_frame)
            return

        if ip.lower() == "b" or mac.lower() == "b":
            clear_add_contact_form()
            update_contacts_list()
            show_frame(contacts_frame)
            return

        contact = Contact(name, ip, mac)
        try:
            append_contact(contact)
            messagebox.showinfo("Saved", "Contact saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save contact: {e}")

        clear_add_contact_form()
        update_contacts_list()
        show_frame(contacts_frame)

    btn_submit_contact = tk.Button(add_contact_frame, text="Submit",
                                   command=submit_contact)
    btn_cancel_contact = tk.Button(add_contact_frame, text="Cancel",
                                   command=lambda: (clear_add_contact_form(),
                                                    show_frame(contacts_frame)))

    btn_submit_contact.grid(row=5, column=0, pady=10, padx=10, sticky="e")
    btn_cancel_contact.grid(row=5, column=1, pady=10, padx=10, sticky="w")

    for i in range(6):
        add_contact_frame.rowconfigure(i, weight=0)
    add_contact_frame.columnconfigure(0, weight=0)
    add_contact_frame.columnconfigure(1, weight=1)

    # ========== INCOMING CALL SCREEN ==========
    ascii_label = tk.Label(incoming_frame,
                           text="\n".join(INCOMING_CALL_ASCII),
                           font=MONO_FONT,
                           justify="left")
    ascii_label.pack(pady=10, padx=10, anchor="w")

    incoming_info_label = tk.Label(incoming_frame, text="", justify="left")
    incoming_info_label.pack(pady=5, padx=10, anchor="w")

    def on_accept():
        nonlocal incoming_call_contact

        chat_client.accept_call()


        messagebox.showinfo("Call", "Call accepted.")
        show_active_call(incoming_call_contact, "Incoming call connected.")

    def on_decline():
        messagebox.showinfo("Call", "Call declined.")
        show_frame(home_frame)

    btn_accept = tk.Button(incoming_frame, text="Accept (A)", command=on_accept)
    btn_decline = tk.Button(incoming_frame, text="Decline (D)", command=on_decline)
    btn_back_home_from_incoming = tk.Button(
        incoming_frame, text="Back to Home",
        command=lambda: show_frame(home_frame)
    )

    btn_accept.pack(side="left", padx=10, pady=10)
    btn_decline.pack(side="left", padx=10, pady=10)
    btn_back_home_from_incoming.pack(side="left", padx=10, pady=10)

    def show_incoming_call(contact: Contact):
        nonlocal incoming_call_contact
        incoming_call_contact = contact
        incoming_info_label.config(
            text=f"Incoming call from {contact.name} "
                 f"(IP {contact.ip_address}; MAC {contact.mac_address})"
        )
        show_frame(incoming_frame)

    # ========== INITIATE CALL SCREEN ==========
    tk.Label(initiate_frame, text="Initiating Call",
             font=("Arial", 14, "bold")).pack(pady=10, anchor="w", padx=10)

    initiate_contact_label = tk.Label(initiate_frame, text="", justify="left")
    initiate_contact_label.pack(pady=5, padx=10, anchor="w")

    initiate_status_label = tk.Label(initiate_frame, text="Calling...", fg="blue", justify="left")
    initiate_status_label.pack(pady=5, padx=10, anchor="w")

    def end_call():
        nonlocal current_outgoing_contact
        # End/cancel the outgoing call
        messagebox.showinfo("Call", "Call ended.")
        current_outgoing_contact = None
        show_frame(home_frame)

    def simulate_answer():
        nonlocal current_outgoing_contact
        # For testing: simulate the remote answering
        initiate_status_label.config(text="Connected", fg="green")
        if not current_outgoing_contact:
            messagebox.showwarning("Call", "No outgoing call to connect.")
            return
        messagebox.showinfo("Call", "Call connected.")
        show_active_call(current_outgoing_contact, "Outgoing call connected.")

    btn_end_call = tk.Button(initiate_frame, text="End Call", command=end_call)
    btn_simulate_answer = tk.Button(initiate_frame, text="Simulate Answer", command=simulate_answer)
    btn_back_home_from_initiate = tk.Button(initiate_frame, text="Back to Home",
                                            command=lambda: show_frame(home_frame))

    btn_end_call.pack(side="left", padx=10, pady=10)
    btn_simulate_answer.pack(side="left", padx=10, pady=10)
    btn_back_home_from_initiate.pack(side="left", padx=10, pady=10)

    def show_initiate_call(contact: Contact):
        nonlocal current_outgoing_contact
        current_outgoing_contact = contact
        initiate_contact_label.config(
            text=f"Calling {contact.name} (IP: {contact.ip_address}; MAC: {contact.mac_address})"
        )
        initiate_status_label.config(text="Ringing...", fg="blue")


        client.send_hello(contact.ip_address, 3456)
        show_frame(initiate_frame)

    # ========== ACTIVE CALL SCREEN ==========
    tk.Label(call_frame, text="In Call",
             font=("Arial", 14, "bold")).pack(pady=10, anchor="w", padx=10)

    call_contact_label = tk.Label(call_frame, text="", justify="left")
    call_contact_label.pack(pady=5, padx=10, anchor="w")

    call_status_label = tk.Label(call_frame, text="", fg="green", justify="left")
    call_status_label.pack(pady=2, padx=10, anchor="w")

    video_surface = tk.Label(call_frame, bd=2, relief="sunken")
    video_surface.pack(padx=10, pady=10)
    

    tk.Label(call_frame,
             text="Live video stream renders in the window above.",
             fg="gray").pack(pady=(0, 10), padx=10, anchor="w")

    def update_video_surface(image=None):
        """Update the video surface with a provided frame or a black placeholder."""
        nonlocal video_photo

        if image is None:
            photo = tk.PhotoImage(width=VIDEO_SURFACE_WIDTH, height=VIDEO_SURFACE_HEIGHT)
            photo.put("black", to=(0, 0, VIDEO_SURFACE_WIDTH, VIDEO_SURFACE_HEIGHT))
        else:
            photo = image

        video_surface.configure(image=photo)
        video_surface.image = photo
        video_photo = photo

    def show_active_call(contact: Contact, status_text: str):
        nonlocal active_call_contact
        active_call_contact = contact
        call_contact_label.config(
            text=f"Connected to {contact.name} (IP: {contact.ip_address}; MAC: {contact.mac_address})"
        )
        call_status_label.config(text=status_text)
        update_video_surface()  # Default to black placeholder until frames arrive
        show_frame(call_frame)

    def end_active_call():
        nonlocal active_call_contact
        if active_call_contact:
            messagebox.showinfo("Call", "Call ended.")
        active_call_contact = None
        show_frame(home_frame)

    btn_end_active = tk.Button(call_frame, text="End Call", command=end_active_call)
    btn_end_active.pack(pady=5, padx=10, anchor="w")

    # Expose helpers so the networking layer can update the call UI when video frames arrive.
    # root.render_video_frame = update_video_surface
    # root.show_call_screen = show_active_call
    # root.end_call_screen = end_active_call
    root.logic_callback = logic_callback
    root.set_chat_client = set_chat_client

    # start on home
    show_frame(home_frame)

    return root


if __name__ == "__main__":
    our_ip = "0.0.0.0"
    our_port = 3456




    app = make_app()
    client = ChatClient(host=our_ip, port=our_port, gui_callback=app.logic_callback)
    app.set_chat_client(client)
    client.start_receiver_thread()
    app.mainloop()
