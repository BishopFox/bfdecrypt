DYLIBS=bfdecrypt.dylib
BFINJECT_SRC=DumpDecrypted.m bfdecrypt.m
MINIZIP_SRC=SSZipArchive/minizip/crypt.c \
SSZipArchive/minizip/ioapi.c \
SSZipArchive/minizip/ioapi_buf.c \
SSZipArchive/minizip/ioapi_mem.c \
SSZipArchive/minizip/minishared.c \
SSZipArchive/minizip/unzip.c \
SSZipArchive/minizip/zip.c \
SSZipArchive/minizip/aes/aes_ni.c \
SSZipArchive/minizip/aes/aescrypt.c \
SSZipArchive/minizip/aes/aeskey.c \
SSZipArchive/minizip/aes/aestab.c \
SSZipArchive/minizip/aes/fileenc.c \
SSZipArchive/minizip/aes/hmac.c \
SSZipArchive/minizip/aes/prng.c \
SSZipArchive/minizip/aes/pwd2key.c \
SSZipArchive/minizip/aes/sha1.c
SSZIPARCHIVE_SRC=SSZipArchive/SSZipArchive.m
OBJS=$(addsuffix .o,$(basename $(BFINJECT_SRC))) \
	$(addsuffix .o,$(basename $(MINIZIP_SRC))) \
	$(addsuffix .o,$(basename $(SSZIPARCHIVE_SRC)))

SDK=$(shell xcodebuild -showsdks| grep iphoneos | awk '{print $$4}')
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

CC=$(shell xcrun --sdk $(SDK) --find clang)
CXX=$(shell xcrun --sdk $(SDK) --find clang++)
LD=$(CXX)
INCLUDES=-I $(SDK_PATH)/usr/include -I SSZipArchive -I SSZipArchive/minizip
ARCHS=-arch arm64

IOS_FLAGS=-isysroot $(SDK_PATH) -miphoneos-version-min=11.0
CFLAGS=$(IOS_FLAGS) -g $(ARCHS) $(INCLUDES) -Wdeprecated-declarations
CXXFLAGS=$(IOS_FLAGS) -g $(ARCHS) $(INCLUDES) -Wdeprecated-declarations

FRAMEWORKS=-framework CoreFoundation -framework IOKit -framework Foundation -framework JavaScriptCore -framework UIKit -framework Security -framework CFNetwork -framework CoreGraphics
LIBS=-lobjc -L$(SDK_PATH)/usr/lib -lz -lsqlite3 -lxml2 -lz -ldl -lSystem #$(SDK_PATH)/usr/lib/libstdc++.tbd 
LDFLAGS=$(IOS_FLAGS) $(ARCHS) $(FRAMEWORKS) $(LIBS)  -ObjC -all_load
MAKE=$(shell xcrun --sdk $(SDK) --find make)

DEVELOPERID=$(shell security find-identity -v -p codesigning | grep "iPhone Developer:" |awk '{print $$2}')

all: $(DYLIBS) 

$(DYLIBS): $(OBJS)
	$(CXX) $(CXXFLAGS) bfdecrypt.o -shared -o bfdecrypt.dylib -dynamic DumpDecrypted.m $(addsuffix .o,$(basename $(MINIZIP_SRC))) \
	$(addsuffix .o,$(basename $(SSZIPARCHIVE_SRC))) \
	$(LIBS) $(FRAMEWORKS) -ObjC
	
$(BINARY_NAME): $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@

%.o: %.mm $(DEPS)
	$(CXX) -c $(CXXFLAGS) $< -o $@

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) $< -o $@

webroot.o: webroot.c

clean:
	rm -f bfdecrypt.o $(OBJS) 2>&1 > /dev/null
	rm -f $(DYLIBS) 2>&1 > /dev/null
