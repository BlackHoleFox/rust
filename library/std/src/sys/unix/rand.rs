use crate::io;

pub fn hashmap_random_keys() -> (u64, u64) {
    const KEY_LEN: usize = core::mem::size_of::<u64>();

    let mut v = [0u8; KEY_LEN * 2];
    // Hashmap randomness doesn't make any promises beyond DoS resistance,
    // so it isn't a fatal
    //
    // Hashmap key generation panics when the RNG is unavailable, like
    // it has historically.
    random_bytes(&mut v, false).expect("failed to access random bytes");

    let key1 = v[0..KEY_LEN].try_into().unwrap();
    let key2 = v[KEY_LEN..].try_into().unwrap();

    (u64::from_ne_bytes(key1), u64::from_ne_bytes(key2))
}

/// Attempts to fill the provided buffer with random bytes from the OS's CSPRNG.
///
/// `require_secure` on Linux and Android controls if an uninitialized, and possibly insecure
/// entropy pool can be used in most cases. This behavior's desirability is dependent
/// on the functionality using it. If `require_secure == true`, this function may block
/// under certain conditons.
///
/// This function fails if the random source is not accessible on a platform, but will always
/// return success (or panic otherwise) obtaining the bytes from it.
pub fn random_bytes(bytes: &mut [u8], require_secure: bool) -> Result<(), io::Error> {
    imp::fill_bytes(bytes, require_secure)
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "watchos"),
    not(target_os = "openbsd"),
    not(target_os = "freebsd"),
    not(target_os = "netbsd"),
    not(target_os = "fuchsia"),
    not(target_os = "redox"),
    not(target_os = "vxworks")
))]
mod imp {
    use crate::io;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "espidf",
        target_os = "horizon"
    ))]
    use crate::io::ErrorKind;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use crate::sys::weak::syscall;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn getrandom(buf: &mut [u8], require_secure: bool) -> Result<libc::ssize_t, io::Error> {
        use crate::sync::atomic::{AtomicBool, Ordering};

        // A weak symbol allows interposition, e.g. for perf measurements that want to
        // disable randomness for consistency. Otherwise, we'll try a raw syscall.
        //
        // (`getrandom` was added in glibc 2.25, musl 1.1.20, android API level 28)
        syscall! {
            fn getrandom(
                buffer: *mut libc::c_void,
                length: libc::size_t,
                flags: libc::c_uint
            ) -> libc::ssize_t
        }

        // This provides the best quality random numbers available at the given moment
        // without ever blocking, and is preferable to falling back to /dev/urandom.
        //
        // It is used for requests like hashmap seeding, which don't promise anything specific.
        static GRND_INSECURE_AVAILABLE: AtomicBool = AtomicBool::new(true);

        // If the caller requires random data that is _always_ cryptographically secure,
        // don't attempt to use `GRND_INSECURE`.
        let flags = if require_secure {
            // Either obtain full-qualiy bytes right away, or block until they're available.
            0
        } else if GRND_INSECURE_AVAILABLE.load(Ordering::Relaxed) {
            // If this call is allowed to return best-effort quality,
            // try `GRND_INSECURE`, and check if its supported.
            let ret = unsafe { getrandom(buf.as_mut_ptr().cast(), buf.len(), libc::GRND_INSECURE) };

            if ret != -1 {
                // The system supported `getrandom` and `GRND_INSECURE`, so a second fallback
                // call isn't needed.
                return Ok(ret);
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::InvalidInput {
                    // the system is too old to support the flag
                    GRND_INSECURE_AVAILABLE.store(false, Ordering::Relaxed);
                } else {
                    // Something else went wrong. Most likely, the system doesn't
                    // support `getrandom`.
                    return Err(err);
                }
            }

            libc::GRND_NONBLOCK
        };

        unsafe { getrandom(buf.as_mut_ptr().cast(), buf.len(), flags) }
    }

    #[cfg(any(target_os = "espidf", target_os = "horizon"))]
    fn getrandom(buf: &mut [u8], _require_secure: bool) -> Result<libc::ssize_t, io::Error> {
        let ret = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        if ret != -1 { Ok(ret) } else { Err(io::Error::last_os_error()) }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "espidf",
        target_os = "horizon"
    )))]
    fn getrandom_fill_bytes(_buf: &mut [u8], _require_secure: bool) -> bool {
        false
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "espidf",
        target_os = "horizon"
    ))]
    fn getrandom_fill_bytes(v: &mut [u8], require_secure: bool) -> bool {
        use crate::sync::atomic::{AtomicBool, Ordering};

        static GETRANDOM_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
        if GETRANDOM_UNAVAILABLE.load(Ordering::Relaxed) {
            return false;
        }

        let mut read = 0;
        while read < v.len() {
            match getrandom(&mut v[read..], require_secure) {
                Ok(copied) => read += result as usize,
                Err(e) => match e.kind() {
                    ErrorKind::Interrupted => continue,
                    ErrorKind::Unsupported | ErrorKind::PermissionDenied => {
                        // Fall back to reading `/dev/urandom` if `getrandom` is not
                        // supported on the current kernel.
                        //
                        // Also fall back in case it is disabled by something like
                        // seccomp or inside of virtual machines.
                        GETRANDOM_UNAVAILABLE.store(true, Ordering::Relaxed);
                        return false;
                    }
                    ErrorKind::WouldBlock => {
                        // Fall back to reading `/dev/urandom` too if a non-critical request
                        // tried to generate bytes but none were available yet. This isn't
                        // reachable if `require_secure == true`.
                        debug_assert!(require_secure == false);
                        return false;
                    }
                    err => panic!("unexpected getrandom error: {err}"),
                },
            }
        }
        true
    }

    pub fn fill_bytes(v: &mut [u8], require_secure: bool) -> Result<(), io::Error> {
        // `getrandom_fill_bytes` can fail here due to these conditions:
        // - `getrandom(2) is not available on the system due to either too old of a kernel or libc.
        // - `getrandom` is unaccessible to due some kind of sandboxing or filter.
        // - `getrandom` returns EAGAIN, and `require_secure == false`
        //
        // In the case of `EAGAIN`, this means that the call would have blocked because
        // the non-blocking entropy source (urandom) was not fully seeded yet. On modern
        // kernels (>= 4.8), this means the kernel's CSPRNG wasn't ready and before that pool
        // did not have a high enough "entropy value" to serve requests. Usually, this means
        // code is running during the very early boot process on Linux.
        //
        // As a fallback, we resort to reading from `/dev/urandom` when `require_secure == false`
        // and/or `getrandom` is not available. There will still be bytes to read, but the values
        // might not be truly random and therefore predictable. This is not ideal
        // when `require_secure == true`, but only so on older kernels and in an environment
        // that already ~usually requires special handling anyway. This is fixable, but not implemented
        // for the reasons above and to keep the code simpler.
        if getrandom_fill_bytes(v, require_secure) {
            return Ok(());
        }

        // Fallback to reading from `/dev/urandom` when `getentropy` is unusable.
        super::read_urandom()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos"))]
mod imp {
    use crate::io;
    use crate::sys::weak::weak;
    use libc::{c_int, c_void, size_t};

    fn getentropy_fill_bytes(v: &mut [u8]) -> bool {
        weak!(fn getentropy(*mut c_void, size_t) -> c_int);

        getentropy
            .get()
            .map(|f| {
                // getentropy(2) permits a maximum buffer size of 256 bytes
                for s in v.chunks_mut(256) {
                    let ret = unsafe { f(s.as_mut_ptr() as *mut c_void, s.len()) };
                    if ret == -1 {
                        panic!("unexpected getentropy error: {}", io::Error::last_os_error());
                    }
                }
                true
            })
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    fn fallback_fill_bytes(v: &mut [u8]) -> Result<(), io::Error> {
        super::read_urandom(v)
    }

    // On iOS and MacOS `SecRandomCopyBytes` calls `CCRandomCopyBytes` with
    // `kCCRandomDefault`. `CCRandomCopyBytes` manages a CSPRNG which is seeded
    // from `/dev/random` and which runs on its own thread accessed via GCD.
    //
    // This is very heavyweight compared to the alternatives, but they may not be usable:
    // - `getentropy` was added in iOS 10, but we support a minimum of iOS 7
    // - `/dev/urandom` is not accessible inside the iOS app sandbox.
    //
    // Therefore `SecRandomCopyBytes` is only used on older iOS versions where no
    // better options are present.
    #[cfg(target_os = "ios")]
    fn fallback_fill_bytes(v: &mut [u8]) -> Result<(), io::Error> {
        use crate::ptr;
        use libc::{c_int, size_t};

        enum SecRandom {}

        #[allow(non_upper_case_globals)]
        const kSecRandomDefault: *const SecRandom = ptr::null();

        extern "C" {
            fn SecRandomCopyBytes(rnd: *const SecRandom, count: size_t, bytes: *mut u8) -> c_int;
        }

        let ret = unsafe { SecRandomCopyBytes(kSecRandomDefault, v.len(), v.as_mut_ptr()) };
        if ret == -1 {
            panic!("couldn't generate random bytes: {}", io::Error::last_os_error());
        }
        Ok(())
    }

    // All supported versions of watchOS (>= 5) have support for `getentropy`.
    #[cfg(target_os = "watchos")]
    #[cold]
    fn fallback_fill_bytes() -> Result<(), io::Error> {
        unreachable!()
    }

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), io::Error> {
        if getentropy_fill_bytes(v) {
            return Ok(());
        }

        // Older macOS versions (< 10.12) don't support `getentropy`. Fallback to
        // reading from `/dev/urandom` on these systems.
        //
        // Older iOS versions (< 10) don't support it either. Fallback to
        // `SecRandomCopyBytes` on these systems. This is unreachable on
        // watchOS because the minimum supported version is 5 while support
        // was added in 3.
        fallback_fill_bytes(v)
    }
}

#[cfg(all(
    unix,
    not(target_os = "ios"),
    not(target_os = "watchos"),
    not(target_os = "openbsd"),
    not(target_os = "freebsd"),
    not(target_os = "netbsd"),
    not(target_os = "fuchsia"),
    not(target_os = "redox"),
    not(target_os = "vxworks")
))]
fn read_urandom(v: &mut [u8]) -> Result<(), crate::io::Error> {
    use crate::fs::File;
    use crate::io::Read;

    // In several cases, most relating to chroots and sandboxing, a process won't be able to access
    // `/dev/urandom`. It is up to the caller to determine if this is fatal or not.
    let mut file = File::open("/dev/urandom")?;
    // If /dev/urandom is accessible, we assume that it will always work.
    file.read_exact(v).expect("failed to read /dev/urandom");
    Ok(())
}

#[cfg(target_os = "openbsd")]
mod imp {
    use crate::io;

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), io::Error> {
        // getentropy(2) permits a maximum buffer size of 256 bytes
        for s in v.chunks_mut(256) {
            let ret = unsafe { libc::getentropy(s.as_mut_ptr() as *mut libc::c_void, s.len()) };
            if ret == -1 {
                panic!("unexpected getentropy error: {}", io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
mod imp {
    use crate::ptr;

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), crate::io::Error> {
        let mib = [libc::CTL_KERN, libc::KERN_ARND];
        // kern.arandom permits a maximum buffer size of 256 bytes
        for s in v.chunks_mut(256) {
            let mut s_len = s.len();
            let ret = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    mib.len() as libc::c_uint,
                    s.as_mut_ptr() as *mut _,
                    &mut s_len,
                    ptr::null(),
                    0,
                )
            };
            if ret == -1 || s_len != s.len() {
                panic!(
                    "kern.arandom sysctl failed! (returned {}, s.len() {}, oldlenp {})",
                    ret,
                    s.len(),
                    s_len
                );
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "fuchsia")]
mod imp {
    #[link(name = "zircon")]
    extern "C" {
        fn zx_cprng_draw(buffer: *mut u8, len: usize);
    }

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), crate::io::Error> {
        unsafe { zx_cprng_draw(v.as_mut_ptr(), v.len()) }
        Ok(())
    }
}

#[cfg(target_os = "redox")]
mod imp {
    use crate::fs::File;
    use crate::io::{self, Read};

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), io::Error> {
        // Open rand:, read from it, and close it again.
        let mut file = File::open("rand:").expect("failed to open rand:");
        file.read_exact(v).expect("failed to read rand:");
        Ok(())
    }
}

#[cfg(target_os = "vxworks")]
mod imp {
    use crate::io;
    use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

    pub fn fill_bytes(v: &mut [u8], _require_secure: bool) -> Result<(), io::Error> {
        static RNG_INIT: AtomicBool = AtomicBool::new(false);
        while !RNG_INIT.load(Relaxed) {
            let ret = unsafe { libc::randSecure() };
            if ret < 0 {
                panic!("couldn't generate random bytes: {}", io::Error::last_os_error());
            } else if ret > 0 {
                RNG_INIT.store(true, Relaxed);
                break;
            }
            unsafe { libc::usleep(10) };
        }
        let ret = unsafe {
            libc::randABytes(v.as_mut_ptr() as *mut libc::c_uchar, v.len() as libc::c_int)
        };
        if ret < 0 {
            panic!("couldn't generate random bytes: {}", io::Error::last_os_error());
        } else {
            Ok(())
        }
    }
}
