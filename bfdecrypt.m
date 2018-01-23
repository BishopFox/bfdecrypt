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
#include "DumpDecrypted.h"

__attribute__ ((constructor)) static void bfinject_rocknroll() {
    NSLog(@"[bfdecrypt] Spawning thread to do decryption in the background...");
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        const char *fullPathStr = _dyld_get_image_name(0);

        NSLog(@"[bfdecrypt] Inside thread. Full path to app: %s", fullPathStr);
        DumpDecrypted *dd = [[DumpDecrypted alloc] initWithPathToBinary:[NSString stringWithUTF8String:fullPathStr]];
        [dd createIPAFile];

        NSLog(@"[bfdecrypt] Over and out.");
    });
    
    NSLog(@"[bfdecrypt] Exiting constructor.");
}
