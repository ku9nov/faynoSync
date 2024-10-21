document.addEventListener('DOMContentLoaded', () => {
    const updateContainer = document.getElementById('update-container');
  
    chrome.storage.local.get(['updateAvailable', 'updateData'], (result) => {
      if (result.updateData && result.updateData.update_available) {
        const data = result.updateData;
  
        updateContainer.innerHTML = '';
  
        const changelogElement = document.createElement('p');
        changelogElement.textContent = `Changelog: ${data.changelog.trim()}`;
        updateContainer.appendChild(changelogElement);
  
        const buttonContainer = document.createElement('div');
        for (const key in data) {
          if (key.startsWith('update_url_')) {
            const packageName = key.substring(11).toUpperCase();
            const button = document.createElement('button');
            button.textContent = packageName;
            button.onclick = () => {
              window.open(data[key], '_blank');
            };
            buttonContainer.appendChild(button);
          }
        }
  
        updateContainer.appendChild(buttonContainer);
      } else {
        updateContainer.innerHTML = '<p>No updates available.</p>';
      }
    });
  });
  