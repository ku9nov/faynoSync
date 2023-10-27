import tkinter as tk
import tkinter.messagebox as messagebox
import config
import requests
import webbrowser


class HelloWorldApp:
    def __init__(self, master, app_name, version, channel, os_name, pc_arch):
        self.master = master
        self.app_name = app_name
        self.version = version
        self.channel = channel
        self.os_name = os_name
        self.pc_arch = pc_arch
        master.title(f"{self.app_name} - v{self.version} ({self.os_name}-{pc_arch})")

        self.label = tk.Label(master, text="Hello, world!")
        self.label.pack()

        url = f"http://localhost:9000/checkVersion?app_name={self.app_name}&version={self.version}&platform={self.os_name}&arch={self.pc_arch}"
        if self.channel:
            url += f"&channel={self.channel}"

        response = requests.get(url)
        print(response.json())

        try:
            data = response.json()
            if data.get("update_available", False):
                message = "You have an older version. Would you like to update your app?"
                if messagebox.askyesno("Update available", message):
                    update_options = [
                        {'name': key.split('_')[-1].upper(), 'url': value}
                        for key, value in data.items()
                        if key.startswith('update_url_')
                    ]
                    self.create_choice_window(update_options)
        except Exception as e:
            print(f"An error occurred: {e}")

    def create_choice_window(self, update_options):
        def open_url(url):
            webbrowser.open(url)

        root = tk.Tk()
        root.title("Choose an update package")

        for i, option in enumerate(update_options):
            button = tk.Button(root, text=option['name'], command=lambda url=option['url']: open_url(url))
            button.pack(pady=5)

        root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    os_name = config.get_os()
    pc_arch = config.get_arch()
    app = HelloWorldApp(
        root,
        app_name=config.app_name,
        version=config.version,
        channel=config.channel,
        os_name=os_name,
        pc_arch=pc_arch
    )
    root.mainloop()
