let updateAvailable = false; 
const appName = 'myapp';
const version = '0.0.1'; 

function getBrowserInfo() {
  const userAgent = navigator.userAgent;
  if (userAgent.includes("Chrome")) {
      return "Chrome";
  } else if (userAgent.includes("Firefox")) {
      return "Firefox";
  } else if (userAgent.includes("Safari")) {
      return "Safari";
  } else if (userAgent.includes("Edg")) {
      return "Edge";
  } else {
      return "Other";
  }
}
function checkUpdates() {
  if (updateAvailable) return;

  const browser = getBrowserInfo();
  const url = `http://localhost:9000/checkVersion?app_name=${appName}&version=${version}&platform=browser&arch=${browser}`;
  
  console.log('Checking for updates...');
  console.log('Request URL:', url); 

  fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network error while checking for updates');
            }
            return response.json();
        })
        .then(data => {
            console.log('Update data:', data);
            if (data.update_available) {
                updateAvailable = true; 
                showUpdateNotification(data);
            } else {
                console.log("No updates available.");
            }
        })
        .catch(error => console.error('Error checking for updates:', error));
}

function showUpdateNotification(data) {
  console.log("Showing update notification");

  chrome.storage.local.set({
    updateAvailable: true,
    updateData: data
  }, () => {
    console.log("Update data saved:", data);
  });
}

function clearUpdateData() {
  chrome.storage.local.set({
    updateAvailable: false,
    updateData: null
  });
}




setInterval(checkUpdates, 2000);
