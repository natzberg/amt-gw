Use a hardcoded AMT video source (`amt://162.250.138.201@232.162.250.140`). The goal is to put the data from the AMT relay onto a local multicast source (currently hardcoded to `239.0.0.1:3000`). Once running, you should be able to playback video in VLC with `udp://@239.0.0.1:3000`.

(You can change a flag in amt-gw.py to  `use_multicast=false` if you want to put it onto 127.0.0.1:3000)

Usage:

```
sudo python3 amt-gw.py 
```
