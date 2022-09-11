use super::{BorrowedBuf, BufWriter, ErrorKind, Read, Result, Write, DEFAULT_BUF_SIZE};
use crate::mem::MaybeUninit;

/// Copies the entire contents of a reader into a writer.
///
/// This function will continuously read data from `reader` and then
/// write it into `writer` in a streaming fashion until `reader`
/// returns EOF.
///
/// On success, the total number of bytes that were copied from
/// `reader` to `writer` is returned.
///
/// If you’re wanting to copy the contents of one file to another and you’re
/// working with filesystem paths, see the [`fs::copy`] function.
///
/// [`fs::copy`]: crate::fs::copy
///
/// # Errors
///
/// This function will return an error immediately if any call to [`read`] or
/// [`write`] returns an error. All instances of [`ErrorKind::Interrupted`] are
/// handled by this function and the underlying operation is retried.
///
/// [`read`]: Read::read
/// [`write`]: Write::write
///
/// # Examples
///
/// ```
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let mut reader: &[u8] = b"hello";
///     let mut writer: Vec<u8> = vec![];
///
///     io::copy(&mut reader, &mut writer)?;
///
///     assert_eq!(&b"hello"[..], &writer[..]);
///     Ok(())
/// }
/// ```
///
/// # Platform-specific behavior
///
/// On Linux (including Android), this function uses `copy_file_range(2)`,
/// `sendfile(2)` or `splice(2)` syscalls to move data directly between file
/// descriptors if possible.
///
/// On other platforms, this will try to use the most efficent OS syscalls to move data
/// directly between file descriptors if possible.
///
/// Note that platform-specific behavior [may change in the future][changes].
///
/// [changes]: crate::io#platform-specific-behavior
#[stable(feature = "rust1", since = "1.0.0")]
pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: Read,
    W: Write,
{
    let copier = Copier { reader, writer };
    CopySpec::copy_to(copier)
}

/// Specializations for a more efficent implementation of copying bytes when the
/// source and destination are file descriptors.
trait CopySpec {
    fn copy_to(self) -> Result<u64>;
}

fn default_copy<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
) -> Result<u64> {
    cfg_if::cfg_if! {
        if #[cfg(any(target_os = "linux", target_os = "android"))] {
            crate::sys::kernel_copy::copy_spec(reader, writer)
        } else {
            generic_copy(reader, writer)
        }
    }
}

struct Copier<'a, R: Read + ?Sized, W: Write + ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
}

impl<R: Read + ?Sized, W: Write + ?Sized> CopySpec for Copier<'_, R, W> {
    default fn copy_to(mut self) -> Result<u64> {
        default_copy(&mut self.reader, &mut self.writer)
    }
}

/// Optimizations for copying a file to another under reasonable conditions
///
/// This only happens on UNIX and Windows because they have optimized APIs for
/// the operation.
#[cfg(any(unix, windows))]
mod file_copy {
    use super::{default_copy, Copier, CopySpec};
    use crate::fs::File;
    use crate::io::{Read, Result, Seek, SeekFrom, Write};
    use crate::sys_common::fs::{CopyInnerFrom, CopyInnerResult, CopyInnerTo};

    #[rustc_specialization_trait]
    trait CopyRead: Read {
        fn params(&mut self) -> &mut File;
    }

    #[rustc_specialization_trait]
    trait CopyWrite: Write {
        fn params(&mut self) -> &mut File;
    }

    // A main goal of this implementation is to avoid any "weird" behavior
    // when using `io::copy` on files that you wouldn't see with the default
    // read/write loop.
    //
    // Things such as:
    // - Copy offets
    // - Destination truncation
    // - Stream positions
    // - Including other writes to the file descriptor (ie; &mut io::Write) in the
    // copy operation.
    impl<R: CopyRead, W: CopyWrite> CopySpec for Copier<'_, R, W> {
        fn copy_to(mut self) -> Result<u64> {
            let reader = self.reader.params();
            let writer = self.writer.params();

            // If both the file handles aren't in the default state, then
            // we fallback so that the behavior matches `io::copy` in leaving/respecting
            // the file/stream position. The OS copy functions don't do this, which would
            // be a behavioral difference.
            if reader.stream_position()? != 0 || writer.stream_position()? != 0 {
                return default_copy(reader, writer);
            }

            // On Windows and macOS, the file copy functions don't work in
            // ranges and will result in truncating the destination if the source
            // is larger. Linux does this correctly, but consistency > narrowness for now.
            if writer.metadata()?.len() != 0 {
                return default_copy(reader, writer);
            }

            // NB: macOS and Windows perform a `File -> Path` mapping operation and write
            // through the path, not the file descriptor. This is generally discouraged due
            // to edge cases but the additional guards help prevent them.
            //
            // macOS's file copy uses a source file descriptor, so it doesn't suffer from the issue
            // (only the destination is passed as a path, which is fine) but on Windows the source
            // is referred to by path too. To avoid missing data that is not associated with the open handle
            // when copying, the Windows implementation will call `fsync` if `copy_inner`'s source is a file.
            //
            // NB: `copy_inner` will utilize the Linux kernel's fast copying for files.
            match crate::sys::fs::copy_inner(CopyInnerFrom::File(reader), CopyInnerTo::File(writer))
            {
                Ok(CopyInnerResult::Ok(r)) => {
                    // Match the behavior of `io::copy` and set the stream positions
                    // for the source and destination to how many bytes were copied.
                    reader.seek(SeekFrom::Start(r))?;
                    writer.seek(SeekFrom::Start(r))?;

                    Ok(r)
                }
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", windows))]
                Ok(CopyInnerResult::PathUnsupported) => {
                    default_copy(&mut self.reader, &mut self.writer)
                }
                Err(e) => Err(e),
            }
        }
    }

    impl CopyRead for File {
        fn params(&mut self) -> &mut File {
            self
        }
    }

    impl CopyWrite for File {
        fn params(&mut self) -> &mut File {
            self
        }
    }
}

/// The userspace read-write-loop implementation of `io::copy` that is used when
/// OS-specific specializations for copy offloading are not available or not applicable.
pub(crate) fn generic_copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: Read,
    W: Write,
{
    BufferedCopySpec::copy_to(reader, writer)
}

/// Specialization of the read-write loop that either uses a stack buffer
/// or reuses the internal buffer of a BufWriter
trait BufferedCopySpec: Write {
    fn copy_to<R: Read + ?Sized>(reader: &mut R, writer: &mut Self) -> Result<u64>;
}

impl<W: Write + ?Sized> BufferedCopySpec for W {
    default fn copy_to<R: Read + ?Sized>(reader: &mut R, writer: &mut Self) -> Result<u64> {
        stack_buffer_copy(reader, writer)
    }
}

impl<I: Write> BufferedCopySpec for BufWriter<I> {
    fn copy_to<R: Read + ?Sized>(reader: &mut R, writer: &mut Self) -> Result<u64> {
        if writer.capacity() < DEFAULT_BUF_SIZE {
            return stack_buffer_copy(reader, writer);
        }

        let mut len = 0;
        let mut init = 0;

        loop {
            let buf = writer.buffer_mut();
            let mut read_buf: BorrowedBuf<'_> = buf.spare_capacity_mut().into();

            unsafe {
                // SAFETY: init is either 0 or the init_len from the previous iteration.
                read_buf.set_init(init);
            }

            if read_buf.capacity() >= DEFAULT_BUF_SIZE {
                let mut cursor = read_buf.unfilled();
                match reader.read_buf(cursor.reborrow()) {
                    Ok(()) => {
                        let bytes_read = cursor.written();

                        if bytes_read == 0 {
                            return Ok(len);
                        }

                        init = read_buf.init_len() - bytes_read;
                        len += bytes_read as u64;

                        // SAFETY: BorrowedBuf guarantees all of its filled bytes are init
                        unsafe { buf.set_len(buf.len() + bytes_read) };

                        // Read again if the buffer still has enough capacity, as BufWriter itself would do
                        // This will occur if the reader returns short reads
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            } else {
                writer.flush_buf()?;
                init = 0;
            }
        }
    }
}

fn stack_buffer_copy<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
) -> Result<u64> {
    let buf: &mut [_] = &mut [MaybeUninit::uninit(); DEFAULT_BUF_SIZE];
    let mut buf: BorrowedBuf<'_> = buf.into();

    let mut len = 0;

    loop {
        match reader.read_buf(buf.unfilled()) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if buf.filled().is_empty() {
            break;
        }

        len += buf.filled().len() as u64;
        writer.write_all(buf.filled())?;
        buf.clear();
    }

    Ok(len)
}
