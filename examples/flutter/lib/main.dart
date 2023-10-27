import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:url_launcher/url_launcher.dart';
import 'dart:io' show Platform;

void main() => runApp(MaterialApp(home: HelloWorldApp()));

class HelloWorldApp extends StatefulWidget {
  @override
  _HelloWorldAppState createState() => _HelloWorldAppState();
}


class _HelloWorldAppState extends State<HelloWorldApp> {
  String appName = "myapp";
  String version = "0.0.1";
  String channel = "nightly";
  late String osName;
  late String pcArch;
  bool updateAvailable = false; 
  List<dynamic> updateOptions = [];

  @override
  void initState() {
    super.initState();
    osName = getOS();
    pcArch = checkArchitecture();
    checkVersion();
  }

  String getOS() {
    if (Platform.isAndroid) {
      return 'android';
    } else if (Platform.isLinux) {
      return getLinuxOS();
    } else if (Platform.isMacOS) {
      return 'darwin';
    } else {
      return Platform.operatingSystem;
    }
  }
  String getLinuxOS() {
    if (Platform.operatingSystem == 'linux') {
      return getLinuxDistribution();
    } else {
      return 'linux';
    }
  }

  String getLinuxDistribution() {
    if (Platform.isLinux) {
      var like = "unknown";

      if (like == "rhel") {
        return "RHEL";
      } else if (like == "debian") {
        return "Debian";
      } else {
        return "Linux";
      }
    } else {
      return 'linux';
    }
  }
  
  String checkArchitecture() {
    if (Platform.isAndroid) {
      return _getAndroidArch();
    } else if (Platform.isIOS) {
      return _getIOSArch();
    } else if (Platform.isLinux) {
      return _getLinuxArch();
    } else if (Platform.isMacOS) {
      return _getMacOSArch();
    } else if (Platform.isWindows) {
      return _getWindowsArch();
    } else {
      return 'Unknown platform';
    }
  }


  String _getAndroidArch() {
    if (Platform.version.contains('64')) {
      return 'arm64';
    } else {
      return 'arm';
    }
  }

  String _getIOSArch() {
    return 'arm64';
  }

  String _getLinuxArch() {
    if (Platform.version.contains('64')) {
      return 'x64';
    } else {
      return 'x86';
    }
  }

  String _getMacOSArch() {
    if (Platform.version.contains('arm')) {
      return 'arm64';
    } else {
      return 'x86_64';
    }
  }

  String _getWindowsArch() {
    if (Platform.version.contains('64')) {
      return 'x64';
    } else {
      return 'x86';
    }
  }

  void checkVersion() async {
    var url = Uri.parse(
        "http://localhost:9000/checkVersion?app_name=$appName&version=$version&platform=$osName&arch=$pcArch");
    if (channel != null) {
      url = Uri.parse(url.toString() + "&channel=$channel");
    }
    print(url);
    var response = await http.get(url);
    var data = jsonDecode(response.body);
    print(data);
    setState(() {
      updateAvailable = data["update_available"] ?? false;
      if (updateAvailable) {
        _showUpdateDialog(data);
      }
    });
  }

  void _showUpdateDialog(Map data) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text("Update Available"),
          content: Text("An update is available. Do you want to install it?"),
          actions: <Widget>[
            TextButton(
              child: Text("No"),
              onPressed: () {
                Navigator.of(context).pop();
              },
            ),
            TextButton(
              child: Text("Yes"),
              onPressed: () {
                Navigator.of(context).pop();
                _openPackageChoiceWindow(data); 
                _displayPackageChoices(); 
              },
            ),
          ],
        );
      },
    );
  }

  void _displayPackageChoices() {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text("Choose Update Package"),
          content: Column(
            children: updateOptions
                .map((option) => ElevatedButton(
                      onPressed: () => openUrl(option['url']),
                      child: Text(option['name']),
                    ))
                .toList(),
          ),
        );
      },
    );
  }


  void _openPackageChoiceWindow(Map data) {
    updateOptions = data.entries
        .where((entry) => entry.key.startsWith('update_url_'))
        .map((entry) =>
            {'name': entry.key.split('_').last.toUpperCase(), 'url': entry.value})
        .toList();
  }

  void openUrl(String url) async {
    if (await canLaunch(url)) {
      await launch(url);
    } else {
      throw 'Could not launch $url';
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: Text("$appName - v$version ($osName-$pcArch)"),
        ),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              Text('Hello, world!'),
              if (updateAvailable)
                Column(
                  children: updateOptions
                      .map((option) => ElevatedButton(
                            onPressed: () => openUrl(option['url']),
                            child: Text(option['name']),
                          ))
                      .toList(),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
