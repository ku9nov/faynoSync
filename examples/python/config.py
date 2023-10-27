import platform
import distro

def get_os():
    system = platform.system().lower()
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
    
def get_arch():
    return  platform.machine() 

app_name = "myapp"
version = "0.0.1"
channel = "nightly"