using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace StorjFileEncryptor
{
    public class Aes128CtrCryptoStream : Stream
    {
        private readonly Stream stream;
        private readonly Lazy<SicBlockCipher> decryptor;
        private readonly AesEngine aes = new AesEngine();

        public Aes128CtrCryptoStream(Stream stream, string key)
        {
            this.stream = stream;

            decryptor = new Lazy<SicBlockCipher>(() => CreateDecryptor(key));
        }

        private SicBlockCipher CreateDecryptor(string key)
        {
            SicBlockCipher decryptor = new SicBlockCipher(aes);
            
            decryptor.Init(false, new ParametersWithIV(new KeyParameter(DecodeKey(key)), new byte[aes.GetBlockSize()]));
            
            return decryptor;
        }

        private static byte[] DecodeKey(string key)
        {
            return
                Enumerable
                    .Range(0, key.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(key.Substring(x, 2), 16))
                    .ToArray();
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        protected override void Dispose(bool disposing)
        {
            stream.Dispose();

            base.Dispose(disposing);
        }

        public override void Flush()
        {
            stream.Flush();
        }

        public override long Length
        {
            get { return stream.Length; }
        }

        public override long Position
        {
            get
            {
                return stream.Position;
            }
            set
            {
                stream.Position = value;
            }
        }

        public override void SetLength(long value)
        {
            stream.SetLength(value);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!CanSeek)
            {
                throw new NotSupportedException();
            }

            return stream.Seek(offset, origin);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!CanWrite)
            {
                throw new NotSupportedException();
            }

            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!CanRead)
            {
                throw new NotSupportedException();
            }

            int decryptedBytesCount = 0;

            while (decryptedBytesCount < count)
            {
                byte[] encrybtedBytes = new byte[aes.GetBlockSize()];
                int read = GetBlock(encrybtedBytes).Result;

                if (read <= 0)
                {
                    break;
                }
                
                byte[] decryptedBytes = new byte[encrybtedBytes.Length];
                decryptor.Value.ProcessBlock(encrybtedBytes, 0, decryptedBytes, 0);

                decryptedBytesCount += read;

                // Copy to buffer
                if (buffer.Length < decryptedBytesCount)
                {
                    Array.Resize(ref buffer, decryptedBytesCount);
                }

                Array.Copy(decryptedBytes, 0, buffer, decryptedBytesCount - read, read);
            }

            return decryptedBytesCount;
        }

        private async Task<int> GetBlock(byte[] buffer)
        {
            int blockSize = aes.GetBlockSize();
            int bytesTotalRead = 0;
            int bytesRead = blockSize;
            byte[] result = new byte[blockSize];

            while (bytesTotalRead < blockSize && bytesRead > 0 && stream.CanRead)
            {
                byte[] output = new byte[blockSize - bytesTotalRead];

                bytesRead = await stream.ReadAsync(output, 0, output.Length);

                if (bytesRead > 0)
                {
                    Array.Copy(output, 0, result, bytesTotalRead, bytesRead);
                }

                bytesTotalRead += bytesRead;
            }

            if (buffer.Length < result.Length)
            {
                Array.Resize(ref buffer, result.Length);
            }

            Array.Copy(result, buffer, result.Length);

            return bytesTotalRead;
        }
    }
}
