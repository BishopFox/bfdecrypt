/*
    BF Decryptor - Decrypt iOS apps and repack them into an .ipa
    https://github.com/BishopFox/bfinject

    Carl Livitt @ Bishop Fox
*/
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <dlfcn.h>
#import <UIKit/UIKit.h>
#include <stdint.h>
#include "DumpDecrypted.h"

#define PORT 31336
//#define DEBUG(...) NSLog(__VA_ARGS__);
#define DEBUG(...) {}

UIWindow *alertWindow = NULL;
UIWindow *kw = NULL;
UIViewController *root = NULL;
UIAlertController *alertController = NULL;
UIAlertController *ncController = NULL;
UIAlertController *errorController = NULL;

// The dylib constructor sets decryptedIPAPath, spawns a thread to do the app decryption, then exits.
__attribute__ ((constructor)) static void bfinject_rocknroll() {
    NSLog(@"[bfdecrypt] Spawning thread to do decryption in the background...");
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{        
        NSLog(@"[bfdecrypt] Inside decryption thread");
        const char *fullPathStr = _dyld_get_image_name(0);
        DumpDecrypted *dd = [[DumpDecrypted alloc] initWithPathToBinary:[NSString stringWithUTF8String:fullPathStr]];
        if(!dd) {
            NSLog(@"[bfdecrypt] ERROR: failed to get DumpDecrypted instance");
            return;
        }

        NSLog(@"[bfdecrypt] Full path to app: %s   ///   IPA File: %@", fullPathStr, [dd IPAPath]);

        dispatch_async(dispatch_get_main_queue(), ^{
            alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
            alertWindow.rootViewController = [UIViewController new];
            alertWindow.windowLevel = UIWindowLevelAlert + 1;
            [alertWindow makeKeyAndVisible];
            
            // Show a "Decrypting!" alert on the device and block the UI
            alertController = [UIAlertController
                alertControllerWithTitle:@"Decrypting"
                message:@"Please wait, this will take a few seconds..."
                preferredStyle:UIAlertControllerStyleAlert];
                
            kw = alertWindow;
            if([kw respondsToSelector:@selector(topmostPresentedViewController)])
                root = [kw performSelector:@selector(topmostPresentedViewController)];
            else
                root = [kw rootViewController];
            root.modalPresentationStyle = UIModalPresentationFullScreen;
            [root presentViewController:alertController animated:YES completion:nil];
        });
        
        // Do the decryption
        [dd createIPAFile];

        // Dismiss the alert box
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];

            // Would the user like to host the IPA on a port for easy retrieval with NetCat?
            NSString *message = @"Would you like to serve the IPA on the following addresses/ports for retrieval with NetCat?\n\n";
            DEBUG(@"Getting IPs");
            NSDictionary *addresses = [dd getIPAddresses];
            DEBUG(@"IP Addresses: %@", addresses);

            id key;
            NSString *ip;
            for(key in addresses) {
                ip = [addresses objectForKey:key];
                message = [NSString stringWithFormat:@"%@%@:31336\n", message, ip];
            }
            message = [NSString stringWithFormat:@"\n\n%@For example:\nnc %@:31336 > /tmp/ecrypted.ipa.", message, ip];

            ncController = [UIAlertController
                        alertControllerWithTitle:@"Decryption Complete!"
                                message:message
                                preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *cancelAction = [UIAlertAction 
                        actionWithTitle:NSLocalizedString(@"No", @"Cancel action")
                                style:UIAlertActionStyleCancel
                                handler:^(UIAlertAction *action)
                                {
                                    NSLog(@"Cancel action");
                                    [ncController dismissViewControllerAnimated:NO completion:nil];
                                    [kw removeFromSuperview];
                                    kw.hidden = YES;
                                    [kw release];
                                }];

            UIAlertAction *okAction = [UIAlertAction 
                        actionWithTitle:NSLocalizedString(@"Yes", @"OK action")
                                style:UIAlertActionStyleDefault
                                handler:^(UIAlertAction *action)
                                {
                                    NSLog(@"OK action");
                                    
                                    // Removing the "Decryption Complete!" alert
                                    [ncController dismissViewControllerAnimated:NO completion:nil];
                                    
                                    // Spawn server on port 31336 by default
                                    // Connections to this port will be sent a raw copy of the IPA file.
                                    NSLog(@"[bfdecrypt] Checking we can start the server...");
                                    int s;
                                    if( ! (s = [dd getSocketForPort:PORT])) {
                                        // Port 31336 isn't available. Something listening?
                                        NSLog(@"[bfdecrypt] Couldn't listen on port %d, is another decrypted app still running?", PORT);
                                        errorController = [UIAlertController
                                            alertControllerWithTitle:@"Error!"
                                                    message:@"Could not start server on port 31336, perhaps there's another decryption server already listening?"
                                                    preferredStyle:UIAlertControllerStyleAlert
                                        ];
                                        [errorController addAction:[UIAlertAction 
                                                                        actionWithTitle:NSLocalizedString(@"Ok", @"Ok")
                                                                                style:UIAlertActionStyleDefault
                                                                                handler:^(UIAlertAction *action)
                                                                                {
                                                                                    NSLog(@"Cancel action");
                                                                                    [errorController dismissViewControllerAnimated:NO completion:nil];
                                                                                    [kw removeFromSuperview];
                                                                                    kw.hidden = YES;
                                                                                    [kw release];
                                                                                }] 
                                        ];
                                        [root presentViewController:errorController animated:YES completion:nil];
                                    } else {
                                        close(s);
                                        NSLog(@"[bfdecrypt] Yes we can, starting now.");
                                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                                            [kw removeFromSuperview];
                                            kw.hidden = YES;
                                            [kw release];
                                            [dd IPAServer:PORT];
                                        });
                                        NSLog(@"[bfdecrypt] IPAServer finished.");
                                    }
                                }];

            [ncController addAction:cancelAction];
            [ncController addAction:okAction];        
            [root presentViewController:ncController animated:YES completion:nil];
        }); // dispatch on main
                    
        NSLog(@"[bfdecrypt] Over and out.");
        while(1)
            sleep(9999999);
    }); // dispatch in background
    
    NSLog(@"[bfdecrypt] All done, exiting constructor.");
}

void showAlert(NSString *title, NSString *message) {
	dispatch_async(dispatch_get_main_queue(), ^{
		UIWindow *alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
    	alertWindow.rootViewController = [UIViewController new];
    	alertWindow.windowLevel = UIWindowLevelAlert + 1;
    	[alertWindow makeKeyAndVisible];

		UIAlertController *alertController = [UIAlertController
					alertControllerWithTitle:title
							message:message
							preferredStyle:UIAlertControllerStyleAlert];
		UIWindow *kw = alertWindow;
		UIViewController *root;
		if([kw respondsToSelector:@selector(topmostPresentedViewController)])
			root = [kw performSelector:@selector(topmostPresentedViewController)];
		else
			root = [kw rootViewController];
		root.modalPresentationStyle = UIModalPresentationFullScreen;

		UIAlertAction *okAction = [UIAlertAction 
				actionWithTitle:NSLocalizedString(@"Ok", @"Ok")
						style:UIAlertActionStyleDefault
						handler:^(UIAlertAction *action)
						{
							[alertController dismissViewControllerAnimated:NO completion:nil];
							[kw removeFromSuperview];
							kw.hidden = YES;
							[kw release];
						}];

		[alertController addAction:okAction];
		[root presentViewController:alertController animated:YES completion:nil];
	});
}