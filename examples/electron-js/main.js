const { app, BrowserWindow, dialog, shell } = require('electron');
const fetch = require('node-fetch');
const os = require('os');
const { version, app_name, channel, owner } = require('./config.js');
const fs = require('fs');

function getLinuxDistributionFamily() {
  let distroFamily = 'Linux';
  try {
    const releaseInfo = fs.readFileSync('/etc/os-release', 'utf8');
    const match = releaseInfo.match(/^ID(?:_LIKE)?=(.*)$/m);
    if (match) {
      const idLike = match[1].trim().toLowerCase();
      if (idLike.includes('rhel') || idLike.includes('fedora') || idLike.includes('centos')) {
        distroFamily = 'RHEL';
      } else if (idLike.includes('debian') || idLike.includes('ubuntu') || idLike.includes('kali')) {
        distroFamily = 'Debian';
      }
    }
  } catch (err) {
    console.error('Error getting Linux distribution family:', err);
  }
  return distroFamily;
}


function createChoiceWindow(updateOptions) {
  const win = new BrowserWindow({
    width: 600,
    height: 400,
    webPreferences: {
      nodeIntegration: true,
    },
  });

  win.loadURL(`data:text/html,
    <html>
      <body>
        <h2>Choose an update package:</h2>
        <ul>
          ${updateOptions
            .map(
              (option, index) =>
                `<li><a id="option-${index}" href="${option.url}">${option.name}</a></li>`
            )
            .join('')}
        </ul>
        <script>
          const { shell } = require('electron');
          document.addEventListener('click', (event) => {
            if (event.target.tagName === 'A') {
              event.preventDefault();
              shell.openExternal(event.target.href);
            }
          });
        </script>
      </body>
    </html>`
  );

  return win;
}

function checkUpdates() {
  let url = `http://localhost:9000/checkVersion?app_name=${app_name}&version=${version}&platform=${os.platform()}&arch=${os.arch()}&owner=${owner}`;

  // Check if the 'channel' variable is set
  if (channel !== undefined) {
    url += `&channel=${channel}`;
  }

  fetch(url, { method: 'GET' })
    .then((res) => res.json())
    .then((data) => {
      console.log(data);
      if (data.update_available) {
        const message = `You have an older version. Would you like to update your app?`;
        dialog.showMessageBox({
          type: 'question',
          title: 'Update available',
          message: message,
          buttons: ['Yes', 'No'],
          defaultId: 0,
        }).then(({ response }) => {
          if (response === 0) {
            const updateOptions = [];
            // Assuming 'data' contains different update URLs
            for (const key in data) {
              if (key.startsWith('update_url_')) {
                updateOptions.push({ name: key.substring(11).toUpperCase(), url: data[key] });
              }
            }
            const choiceWindow = createChoiceWindow(updateOptions);
          }
        });
      }
    })
    .catch(() => {});
}

function createWindow() {
  let osName = os.platform();
  let pcArch = os.arch();
  if (osName === 'linux') {
    osName = getLinuxDistributionFamily();
  }
  const title = `${app_name} - v${version} (${osName}-${pcArch})`;

  let win = new BrowserWindow({
    width: 400,
    height: 300,
    webPreferences: {
      nodeIntegration: true,
    },
  });

  win.setTitle(title);
  win.loadFile('index.html');
  win.on('closed', () => {
    win = null;
  });

  checkUpdates();
}

app.whenReady().then(createWindow);