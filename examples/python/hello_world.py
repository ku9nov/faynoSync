import tkinter as tk
import tkinter.messagebox as messagebox
import config
import requests

class HelloWorldApp:
    def __init__(self, master, app_name, version, channel, os_name):
        self.master = master
        self.app_name = app_name
        self.version = version
        self.channel = channel
        self.os_name = os_name
        master.title(f"{self.app_name} - v{self.version} ({self.os_name})")

        self.label = tk.Label(master, text="Hello, world!")
        self.label.pack()

        # Check if the 'channel' variable is set
        if hasattr(self, 'channel'):
            url = f"http://localhost:9000/checkVersion?app_name={self.app_name}&version={self.version}&channel_name={self.channel}"
        else:
            url = f"http://localhost:9000/checkVersion?app_name={self.app_name}&version={self.version}"

        # Make POST request to check for updates
        response = requests.post(url)
        print(response.json())

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
    app = HelloWorldApp(root, app_name=config.app_name, version=config.version, channel=config.channel, os_name=os_name)
    root.mainloop()