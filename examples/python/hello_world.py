import tkinter as tk
import tkinter.messagebox as messagebox
import config
import requests

class HelloWorldApp:
    def __init__(self, master, app_name, version, os_name):
        self.master = master
        self.app_name = app_name
        self.version = version
        self.os_name = os_name
        master.title(f"{self.app_name} - v{self.version} ({self.os_name})")

        self.label = tk.Label(master, text="Hello, world!")
        self.label.pack()

        # Make POST request to check for updates
        url = f"http://localhost:9000/checkVersion?app_name={self.app_name}&version={self.version}"
        response = requests.post(url)

        # Parse response and show update message if needed
        try:
            data = response.json()
            if data["update_available"]:
                message = f"You have an older version. Would you like to update your app?"
                if messagebox.askyesno("Update available", message):
                    import webbrowser
                    webbrowser.open(data['update_url'])
        except:
            pass

if __name__ == "__main__":
    root = tk.Tk()
    os_name = config.get_os()
    app = HelloWorldApp(root, app_name=config.app_name, version=config.version, os_name=os_name)
    root.mainloop()