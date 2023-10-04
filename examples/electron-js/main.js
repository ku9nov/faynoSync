const { app, BrowserWindow, dialog } = require('electron');
const fetch = require('node-fetch');
const os = require('os');
const { version, app_name, channel } = require('./config.js');
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

function checkUpdates() {
  let url = `http://localhost:9000/checkVersion?app_name=${app_name}&version=${version}`;

  // Check if the 'channel' variable is set
  if (channel !== undefined) {
      url += `&channel_name=${channel}`;
  }
  console.log(url)
  fetch(url, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
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
            require('electron').shell.openExternal(data.update_url);
          }
        });
      }
    })
    .catch(() => {});
}

function createWindow() {
  let osName = os.platform();
  if (osName === 'linux') {
    osName = getLinuxDistributionFamily();
  }
  const title = `${app_name} - v${version} (${osName})`;

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