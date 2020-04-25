#define __COREFOUNDATION_CFUSERNOTIFICATION__ 1
#import <CoreFoundation/CoreFoundation.h>
#undef __COREFOUNDATION_CFUSERNOTIFICATION__

#import <Foundation/Foundation.h>

#import <sys/mman.h>
#import <sys/stat.h>
#import <notify.h>

#import "CaptainHook/CaptainHook.h"
#import "CFUserNotification.h"

extern NSString *MFDataGetDataPath(void);

static void ringAlarms(void)
{
	notify_post("com.rpetrich.mailfix.potential-exploitation");
}

@interface MFData : NSData
@end

@interface MFMutableData : NSMutableData {
	void *_bytes;
	NSUInteger _length;
	NSUInteger _mappedLength;
	NSUInteger _capacity;
	NSUInteger _threshold;
	char *_path;
	int _fd;
	NSUInteger _flushFrom;
	BOOL _flush;
	BOOL _immutable;
	BOOL _vm;
}

- (void)_flushToDisk:(NSUInteger)flushSize capacity:(NSUInteger)capacity;
- (void)_mapMutableData:(BOOL)useOnDiskLength;

@end

@interface NSFileManager (NSFileManagerAdditions)
- (NSString *)mf_makeUniqueFileInDirectory:(NSString *)directory;
@end

%hook MFMutableData

- (void)_flushToDisk:(NSUInteger)flushSize capacity:(NSUInteger)capacity
{
	void **_bytes = CHIvarRef(self, _bytes, void *);
	NSUInteger *_length = CHIvarRef(self, _length, NSUInteger);
	NSUInteger *_mappedLength = CHIvarRef(self, _mappedLength, NSUInteger);
	NSUInteger *_capacity = CHIvarRef(self, _capacity, NSUInteger);
	char **_path = CHIvarRef(self, _path, char *);
	int *_fd = CHIvarRef(self, _fd, int);
	NSUInteger *_flushFrom = CHIvarRef(self, _flushFrom, NSUInteger);
	BOOL *_flush = CHIvarRef(self, _flush, BOOL);
	BOOL *_vm = CHIvarRef(self, _vm, BOOL);
	BOOL flush;
	if (*_path != NULL) {
		const char *path = [[[NSFileManager defaultManager] mf_makeUniqueFileInDirectory:MFDataGetDataPath()] fileSystemRepresentation];
		if (path == nil) {
			ringAlarms();
			[NSException raise:NSInternalInconsistencyException format:@"Failed to create or copy temporary cache file path."];
		}
		*_path = strdup(path);
		flush = YES;
	} else {
		flush = *_flush;
		if (!flush) {
			ringAlarms();
			[NSException raise:NSInternalInconsistencyException format:@"Requested flushing, but without the flush flag set."];
		}
	}
	if (!flush) {
		return;
	}
	if ((*_fd == -1) && ((*_fd = open(*_path, O_CREAT | O_RDWR)) == -1)) {
		*_capacity = capacity;
		free(*_path);
		*_path = NULL;
	} else {
		if (*_length != 0) {
			int result = lseek(*_fd, *_flushFrom, SEEK_SET);
			if (result == -1) {
				// panic if failed to seek
				ringAlarms();
				[NSException raise:NSInternalInconsistencyException format:@"Failed to seek."];
			}
			result = write(*_fd, &[self bytes][*_flushFrom], capacity);
			if (result == -1) {
				// panic if failed to write
				ringAlarms();
				[NSException raise:NSInternalInconsistencyException format:@"Failed to write."];
			}
		}
		if ((flushSize != capacity) || (*_capacity != capacity)) {
			int result = ftruncate(*_fd, capacity);
			if (result == -1) {
				// panic if failed to truncate
				ringAlarms();
				[NSException raise:NSInternalInconsistencyException format:@"Failed to truncate."];
			}
		}
		if (*_bytes != NULL) {
			if (*_vm) {
				NSDeallocateMemoryPages(*_bytes, *_mappedLength);
			} else {
				free(*_bytes);
			}
		}
	}
}

- (void)_mapMutableData:(BOOL)useOnDiskLength
{
	void **_bytes = CHIvarRef(self, _bytes, void *);
	NSUInteger *_length = CHIvarRef(self, _length, NSUInteger);
	NSUInteger *_mappedLength = CHIvarRef(self, _mappedLength, NSUInteger);
	NSUInteger *_capacity = CHIvarRef(self, _capacity, NSUInteger);
	int *_fd = CHIvarRef(self, _fd, int);
	char **_path = CHIvarRef(self, _path, char *);
	BOOL *_immutable = CHIvarRef(self, _immutable, BOOL);
	BOOL *_vm = CHIvarRef(self, _vm, BOOL);
	int fd = *_fd;
	if (fd == -1) {
		if (*_path == NULL) {
			// panic if path is null
			ringAlarms();
			[NSException raise:NSInternalInconsistencyException format:@"Expected a path."];
		}
		fd = open(*_path, O_RDONLY);
		if (fd == -1) {
			// panic if cannot open
			ringAlarms();
			[NSException raise:NSInternalInconsistencyException format:@"Expected open to succeed."];
		}
	}
	struct stat buf;
	int result = fstat(fd, &buf);
	if (result == -1) {
		close(fd);
		ringAlarms();
		[NSException raise:NSInternalInconsistencyException format:@"Expected fstat to succeed."];
	}
	if (buf.st_size > 0) {
		void *mapped = mmap(NULL, buf.st_size, *_immutable ? PROT_READ : (PROT_READ|PROT_WRITE), MAP_PRIVATE, *_fd, 0);
		if (mapped == MAP_FAILED) {
			// panic if mmap fails
			ringAlarms();
			[NSException raise:NSInternalInconsistencyException format:@"Expected mmap to succeed."];
		}
		*_vm = YES;
		if (useOnDiskLength) {
			*_length = buf.st_size;
		}
		*_capacity = buf.st_size;
		*_mappedLength = buf.st_size;
	} else {
		*_bytes = calloc(8, 1);
		*_length = 0;
		*_capacity = 8;
	}
	if (fd != *_fd) {
		close(fd);
	}
}

%end

static CFUserNotificationRef pendingNotification;
static void displayAlert(void)
{
	CFUserNotificationRef notification = pendingNotification;
	if (notification != NULL) {
		pendingNotification = NULL;
		CFUserNotificationCancel(notification);
		CFRelease(notification);
	}
	const CFTypeRef keys[] = {
		kCFUserNotificationAlertTopMostKey,
		kCFUserNotificationAlertHeaderKey,
		kCFUserNotificationAlertMessageKey
	};
	const CFTypeRef values[] = {
		kCFBooleanTrue,
		CFSTR("MailFix"),
		CFSTR("Detected an attempt to exploit vulnerabilities in MIME.framework's MFMutableData class"),
	};
	CFDictionaryRef dict = CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys, (const void **)values, sizeof(keys) / sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SInt32 err = 0;
	pendingNotification = CFUserNotificationCreate(kCFAllocatorDefault, 0, kCFUserNotificationPlainAlertLevel, &err, dict);
	CFRelease(dict);
}

static void receivedNotification(CFNotificationCenterRef center, void *observer, CFNotificationName name, const void *object, CFDictionaryRef userInfo)
{
	displayAlert();
}

%ctor {
	if ([[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, receivedNotification, CFSTR("com.rpetrich.mailfix.potential-exploitation"), NULL, CFNotificationSuspensionBehaviorHold);
	}
	%init();
}
