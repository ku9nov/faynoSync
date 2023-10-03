import platform
import distro

def get_os():
    system = platform.system()
    if system == "Linux":
        info = distro.info()
        if info["like"] == "rhel":
            return "RHEL"
        elif info["like"] == "debian":
            return "Debian"
        else:
            return "Linux"
    else:
        return system
app_name = "myapp"
version = "1.0.0"