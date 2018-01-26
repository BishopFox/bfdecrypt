# bfdecrypt
Utility to decrypt App Store apps on jailbroken iOS 11.x

## Decrypt App Store apps on LiberiOS
Here's an example using https://github.com/BishopFox/bfinject to decrypt the Reddit app on an Electra-jailbroken iPhone:

```
Cs-iPhone:~ root# bash bfinject -P Reddit -l dylibs/bfdecrypt.dylib
[+] Electra detected.
[+] Injecting into '/var/containers/Bundle/Application/BCEBDD64-6738-45CE-9B3C-C6F933EA0793/Reddit.app/Reddit'
[+] Getting Team ID from target application...
[+] Thinning dylib into non-fat arm64 image
[+] Signing injectable .dylib with Team ID 2TDUX39LX8 and platform entitlements...
[bfinject4realz] Calling task_for_pid() for PID 3218.
[bfinject4realz] Calling thread_create() on PID 3218
[bfinject4realz] Looking for ROP gadget... found at 0x1016a5110
[bfinject4realz] Fake stack frame at 0x10a06c000
[bfinject4realz] Calling _pthread_set_self() at 0x181303814...
[bfinject4realz] Returned from '_pthread_set_self'
[bfinject4realz] Calling dlopen() at 0x1810c3460...
[bfinject4realz] Returned from 'dlopen'
[bfinject4realz] Success! Library was loaded at 0x1c03e1100
[+] So long and thanks for all the fish.
```

You'll see this screen on your device:

<img src="https://i.imgur.com/z8HkeIB.png" width="400px"/>

Once it's complete, you'll be presented with a UI alert to ask if you want to spawn a service from which you can download your decrypted IPA:

<img src="https://i.imgur.com/cf30n2L.png" width="400px"/>

If you tap `Yes`, a service will be spawned on port 31336 of your device. Connect to it and you'll be sent a raw copy of the IPA that can be downloaded with netcat like so:

```bash
carl@calisto-3 /tmp $ nc 192.168.1.33 31336 > decrypted.ipa
carl@calisto-3 /tmp $ ls -l decrypted.ipa
-rw-r--r--  1 carl  wheel  14649063 Jan 25 16:57 decrypted.ipa
carl@calisto-3 /tmp $ file decrypted.ipa
decrypted.ipa: iOS App Zip archive data, at least v2.0 to extract
```

Alternatively, check the console log for the device, it will tell you where the decrypted IPA is stored. For example:

```
[dumpdecrypted] Wrote /var/mobile/Containers/Data/Application/6E6A5887-8B58-4FC5-A2F3-7870EDB5E8D1/Documents/decrypted-app.ipa
```

You can also search the filesystem for the IPA like so:

```
find /var/mobile/Containers/Data/Application/ -name decrypted-app.ipa
```

Getting the .ipa off the device can be done with netcat. On your laptop, set up a listener service:

```
ncat -l 0.0.0.0 12345 > decrypted.ipa
```

And on the jailbroken device:

```
cat /path/to/decrypted.ipa > /dev/tcp/<IP_OF_YOUR_COMPUTER>/12345
````

The .ipa will be a clone of the original .ipa from the App Store, except that the main binary and all its accompanying frameworks and shared libraries will be decrypted. The CRYPTID flag will be 0 in each previously-encrypted file. You can take the .ipa, extract the app, modify it as needed, re-sign it with your own developer cert, and deploy it onto non-jailbroken devices as needed.

## Compatibility
This is been tested successfully with Electra and LiberiOS.
