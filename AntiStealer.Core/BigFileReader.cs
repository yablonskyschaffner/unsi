// Section 5.5 — memory-mapped IO for samples larger than the buffered
// path can comfortably hold in heap. Using MemoryMappedFile lets the
// kernel page in only the regions of the file we touch (e.g. the PE
// header, the import table, sampled chunks for entropy) instead of
// pre-loading every byte into a managed array. For hot scans of
// multi-hundred-MiB installers this avoids a large LOH allocation
// and keeps RSS bounded.
//
// Cross-platform: MemoryMappedFile is available on every TFM .NET 8
// supports (Windows, Linux, macOS). The wrapper is a thin
// IDisposable that exposes a ReadOnlyMemory<byte> view + a length;
// callers that want a Span can call .Span themselves.
using System;
using System.IO;
using System.IO.MemoryMappedFiles;

namespace AntiStealerOneExe
{
    /// <summary>
    /// File above this length is opened via <see cref="MemoryMappedFile"/>
    /// in <see cref="BigFileReader.Open"/>. Smaller files use the simple
    /// <see cref="File.ReadAllBytes"/> path because the syscall overhead
    /// of mapping a small file dominates the savings.
    /// </summary>
    public sealed class BigFileReader : IDisposable
    {
        public const long DefaultThresholdBytes = 50L * 1024 * 1024;

        private readonly MemoryMappedFile?           _mmf;
        private readonly MemoryMappedViewAccessor?   _accessor;
        private readonly byte[]?                     _heap;
        private bool _disposed;

        public long Length { get; }

        private BigFileReader(MemoryMappedFile mmf, MemoryMappedViewAccessor accessor, long length)
        {
            _mmf      = mmf;
            _accessor = accessor;
            _heap     = null;
            Length    = length;
        }

        private BigFileReader(byte[] heap)
        {
            _mmf      = null;
            _accessor = null;
            _heap     = heap;
            Length    = heap.LongLength;
        }

        /// <summary>
        /// Opens <paramref name="path"/> for read. Files at or above
        /// <paramref name="thresholdBytes"/> are memory-mapped; smaller
        /// files are loaded into a heap byte[]. The returned reader is
        /// IDisposable — disposing it releases the mapping handle.
        /// </summary>
        public static BigFileReader Open(string path, long thresholdBytes = DefaultThresholdBytes)
        {
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException(path);
            if (info.Length < thresholdBytes)
            {
                return new BigFileReader(File.ReadAllBytes(path));
            }
            // FileShare.ReadWrite so other tools (yara/clamscan helpers
            // started in parallel) can still open the same sample.
            var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            try
            {
                var mmf = MemoryMappedFile.CreateFromFile(
                    fileStream: fs,
                    mapName: null,
                    capacity: 0,
                    access: MemoryMappedFileAccess.Read,
                    inheritability: System.IO.HandleInheritability.None,
                    leaveOpen: false);
                var accessor = mmf.CreateViewAccessor(0, info.Length, MemoryMappedFileAccess.Read);
                return new BigFileReader(mmf, accessor, info.Length);
            }
            catch
            {
                fs.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Reads <paramref name="count"/> bytes starting at
        /// <paramref name="offset"/> into <paramref name="destination"/>.
        /// Throws if the request runs past EOF.
        /// </summary>
        public int ReadAt(long offset, Span<byte> destination, int count)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(BigFileReader));
            if (offset < 0 || count < 0 || offset + count > Length)
                throw new ArgumentOutOfRangeException();
            if (count == 0) return 0;
            if (_heap != null)
            {
                var src = _heap.AsSpan(checked((int)offset), count);
                src.CopyTo(destination);
                return count;
            }
            // MMF path: copy through a small stack buffer to avoid
            // allocating a temporary heap array per read.
            int copied = 0;
            Span<byte> stack = stackalloc byte[4096];
            while (copied < count)
            {
                int chunk = Math.Min(stack.Length, count - copied);
                _accessor!.ReadArray(offset + copied, _scratch ??= new byte[stack.Length], 0, chunk);
                _scratch.AsSpan(0, chunk).CopyTo(destination.Slice(copied));
                copied += chunk;
            }
            return copied;
        }

        // The MMF accessor lacks a Span-returning Read; we rent one heap
        // scratch per reader to keep allocations off the hot loop.
        private byte[]? _scratch;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _accessor?.Dispose(); } catch { }
            try { _mmf?.Dispose();      } catch { }
        }
    }
}
