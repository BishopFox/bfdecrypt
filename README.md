# bfdecrypt
Utility to decrypt App Store apps on jailbroken iOS 11.x

## Decrypt App Store apps on LiberiOS
Here's an example using https://github.com/BishopFox/bfinject to decrypt an the app running with PID 802:

```
-bash-3.2# pwd
/var/bfinject
-bash-3.2# bash bfinject -p 802 -l /path/to/decrypt.dylib
[+] Injecting into '/var/containers/Bundle/Application/DD0F3B57-555E-4DDE-B5B0-95E5BA567C5C/redacted.app/redacted'
... magic happens...
[+] So long and thanks for all the fish.
```

Check the console log for the device, it will tell you where the decrypted IPA is stored. For example:

```
[dumpdecrypted] Wrote /var/mobile/Containers/Data/Application/6E6A5887-8B58-4FC5-A2F3-7870EDB5E8D1/Documents/decrypted-app.ipa
```

Getting the .ipa off the device can be done with netcat. On your laptop:

```
ncat -l 0.0.0.0 12345 > decrypted.ipa
```

And on the jailbroken device:

```
cat /path/to/decrypted.ipa > /dev/tcp/<IP_OF_YOUR_COMPUTER>/12345
````

The .ipa will be a clone of the original .ipa from the App Store, except that the main binary and all its accompanying frameworks and shared libraries will be decrypted. The CRYPTID flag will be 0 in each previously-encrypted file. You can take the .ipa, extract the app, modify it as needed, re-sign it with your own developer cert, and deploy it onto non-jailbroken devices as needed.

## Electra
This is untested, but you should be able to use `decrypt.dylib` with this command on Electra:

```
/bootstrap/inject_criticald PID /path/to/decrypt.dylib.
```

Again, check the console log to find the location of the IPA file. Let me know if it works!
