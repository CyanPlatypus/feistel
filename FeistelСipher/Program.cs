using System;
using System.Collections;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace FeistelСipher
{
    class Program
    {
        static void Main(string[] args)
        {
            var str = "Super secret code";
            var f = new Feistel();
            //int roundNum = 12;

            for (int roundNum = 1; roundNum < 13; roundNum++)
            {
                var bytesForward = f.CBCForward(str, roundNum);
                var bytesBack = f.CBCBack(bytesForward, roundNum);

                Console.WriteLine($"Rounds: {roundNum}{Environment.NewLine}" +
                                  $"Plaintext:    {str}{Environment.NewLine}" +
                                  $"CipherText:   {FromArrBytesToString(bytesForward)}{Environment.NewLine}" +
                                  $"DecipherText: {FromArrBytesToString(bytesBack)}{Environment.NewLine}");
            }

            for (int roundNum = 1; roundNum < 13; roundNum++)
            {
                var bytesForward = f.CFBForward(str, roundNum);
                var bytesBack = f.CFBBack(bytesForward, roundNum);

                Console.WriteLine($"Rounds: {roundNum}{Environment.NewLine}" +
                                  $"Plaintext:    {str}{Environment.NewLine}" +
                                  $"CipherText:   {FromArrBytesToString(bytesForward)}{Environment.NewLine}" +
                                  $"DecipherText: {FromArrBytesToString(bytesBack)}{Environment.NewLine}");
            }

            Console.ReadLine();
        }

        public static System.Text.Encoding encoding = new System.Text.UnicodeEncoding();//.ASCIIEncoding();
        
        public static byte[] FromStringToArrBytes(string str) => encoding.GetBytes(str);//str.ToCharArray().Select(c => Convert.ToByte(c)).ToArray();

        public static string FromArrBytesToString(byte[] bytes) => encoding.GetString(bytes);//new string(bytes.Select(c => Convert.ToChar(c)).ToArray());
        
        public static byte[] FromArrayUInt32ToArrayByte(UInt32[] ints)
        {
            var newBytes = new byte[ints.Length * 4];
            int j = 0;
            for (int i = 0; i < ints.Length; i++)
            {
                newBytes[j++] = (byte)(ints[i] >> 24);
                newBytes[j++] = (byte)(ints[i] >> 16);
                newBytes[j++] = (byte)(ints[i] >> 8);
                newBytes[j++] = (byte)(ints[i]);
            }

            return newBytes;
        }

        public static UInt32[] FromArrayByteToArrayUInt32(byte[]  bytes)
        {
            var ints = new UInt32[bytes.Length / 4];
            for (int octetNum = 0; octetNum < bytes.Length / 4; octetNum++)
            {
                var bytestToInt = new byte[4];
                for (int positionInOctet = octetNum * 4, i = 0; positionInOctet < octetNum * 4 + 4; positionInOctet++, i++)
                {
                    bytestToInt[i] = bytes[positionInOctet];
                }

                ints[octetNum] = BitConverter.ToUInt32(bytestToInt.Reverse().ToArray(), 0);
            }

            return ints;
        }

        public static UInt32 CyclRight(UInt32 num, int bitCount)
        {
            return (num >> bitCount) | (num << (32 - bitCount%32));
        }

        public static UInt64 CyclRight(UInt64 num, int bitCount)
        {
            return (num >> bitCount) | (num << (64 - bitCount%64));
        }

        public static UInt32 CyclLeft(UInt32 num, int bitCount)
        {
            return (num << bitCount) | (num >> (32 - bitCount%32));
        }

        public static UInt64 CyclLeft(UInt64 num, int bitCount)
        {
            return (num << bitCount) | (num >> (64 - bitCount%64));
        }

    }

    public class Feistel
    {
        protected static Random random = new Random();

        protected UInt64 _key;

        protected UInt32 _initVectorLeft;
        protected UInt32 _initVectorRight;

        public Feistel()
        {
            CreateKey();
            CreateInitVector();
        }

        protected void CreateKey()
        {
            var byteKey = new byte[8];
            random.NextBytes(byteKey);
            _key = BitConverter.ToUInt64(byteKey, 0);
        }

        protected void CreateInitVector()
        {
            var byteKey = new byte[4];
            random.NextBytes(byteKey);
            _initVectorLeft = BitConverter.ToUInt32(byteKey, 0);
            random.NextBytes(byteKey);
            _initVectorRight = BitConverter.ToUInt32(byteKey, 0);
        }

        protected void MakeLenMult64bit(ref byte[] bytes)
        {
            var len = bytes.Length;

            if (len % 8 > 0)
            {
                var array2 = Enumerable.Repeat((byte)0, 8 - bytes.Length % 8).ToArray();// new byte[8 - bytes.Length % 8];
                Array.Resize(ref bytes, len + array2.Length);
                Array.Copy(array2, 0, bytes, len, array2.Length);
            }

            //Array.Resize(ref bytes, bytes.Length + 8 - bytes.Length % 8);

        }
        
        #region usual
        public byte[] ChiForward(string str, int rounfCount)
        {
            //convert string to byte[]
            var bytes = Program.FromStringToArrBytes(str);

            return Chi(bytes, rounfCount, false);
        }

        public byte[] ChiBack(byte[] bytes, int rounfCount)
        {
            return Chi(bytes, rounfCount, true);
        }

        protected byte[] Chi(byte[] bytes, int rounfCount, bool isBack)
        {
            //add 0 bytes to the end of byte[] so byte[] has appropriate len
            MakeLenMult64bit(ref bytes);
            
            //convert byte[] to int[] (Toint32(byte[](from i to i+4)))
            var ints = Program.FromArrayByteToArrayUInt32(bytes);

            //take two ints as input into festel cipher
            for (int pairNum = 0; pairNum < ints.Length; pairNum += 2)
            {
                UInt32 left = ints[pairNum];
                UInt32 right = ints[pairNum + 1];
                FCi(ref left, ref right, rounfCount, isBack);

                ints[pairNum] = left;
                ints[pairNum + 1] = right;
            }

            //from int array to byte array
            var newBytes = Program.FromArrayUInt32ToArrayByte(ints);

            return newBytes;
        }

        #endregion

        #region cbc
        public byte[] CBCForward(string str, int rounfCount)
        {
            //convert string to byte[]
            var bytes = Program.FromStringToArrBytes(str);

            return Chi(bytes, rounfCount, false);
        }

        public byte[] CBCBack(byte[] bytes, int rounfCount)
        {
            return Chi(bytes, rounfCount, true);
        }

        protected byte[] CBC(byte[] bytes, int rounfCount, bool isBack)
        {
            //add 0 bytes to the end of byte[] so byte[] has appropriate len
            MakeLenMult64bit(ref bytes);

            //convert byte[] to int[] (Toint32(byte[](from i to i+4)))
            var ints = Program.FromArrayByteToArrayUInt32(bytes);

            if (!isBack)
            {
                var initLeft = _initVectorLeft;
                var initRight = _initVectorRight;

                //take two ints as input into festel cipher
                for (int pairNum = 0; pairNum < ints.Length; pairNum += 2)
                {
                    UInt32 left = initLeft ^ ints[pairNum];
                    UInt32 right = initRight ^ ints[pairNum + 1];

                    FCi(ref left, ref right, rounfCount, isBack);

                    ints[pairNum] = left;
                    ints[pairNum + 1] = right;

                    initLeft = left;
                    initRight = right;
                }
            }
            else
            {
                var initLeft = _initVectorLeft;
                var initRight = _initVectorRight;

                var prevInitLeft = _initVectorLeft;
                var prevInitRight = _initVectorRight;

                //take two ints as input into festel cipher
                for (int pairNum = 0; pairNum < ints.Length; pairNum += 2)
                {
                    UInt32 left = initLeft = ints[pairNum];
                    UInt32 right = initRight = ints[pairNum + 1];

                    FCi(ref left, ref right, rounfCount, isBack);

                    ints[pairNum] = prevInitLeft ^ left;
                    ints[pairNum + 1] = prevInitRight ^ right;

                    prevInitLeft = initLeft;
                    prevInitRight = initRight;
                }

            }

            //from int array to byte array
            var newBytes = Program.FromArrayUInt32ToArrayByte(ints);

            return newBytes;
        }
        #endregion

        #region cbc
        public byte[] CFBForward(string str, int rounfCount)
        {
            //convert string to byte[]
            var bytes = Program.FromStringToArrBytes(str);

            return Chi(bytes, rounfCount, false);
        }

        public byte[] CFBBack(byte[] bytes, int rounfCount)
        {
            return Chi(bytes, rounfCount, true);
        }

        protected byte[] CFB(byte[] bytes, int rounfCount, bool isBack)
        {
            //add 0 bytes to the end of byte[] so byte[] has appropriate len
            MakeLenMult64bit(ref bytes);

            //convert byte[] to int[] (Toint32(byte[](from i to i+4)))
            var ints = Program.FromArrayByteToArrayUInt32(bytes);

            if (!isBack)
            {
                var initLeft = _initVectorLeft;
                var initRight = _initVectorRight;

                //take two ints as input into festel cipher
                for (int pairNum = 0; pairNum < ints.Length; pairNum += 2)
                {
                    UInt32 left  = initLeft;
                    UInt32 right = initRight;

                    FCi(ref left, ref right, rounfCount, isBack);

                    ints[pairNum] = left ^ ints[pairNum];
                    ints[pairNum + 1] = right ^ ints[pairNum + 1];

                    initLeft = ints[pairNum];
                    initRight = ints[pairNum + 1];
                }
            }
            else
            {
                var initLeft = _initVectorLeft;
                var initRight = _initVectorRight;

                var prevInitLeft = _initVectorLeft;
                var prevInitRight = _initVectorRight;

                //take two ints as input into festel cipher
                for (int pairNum = 0; pairNum < ints.Length; pairNum += 2)
                {
                    UInt32 left = initLeft;// = ints[pairNum];
                    UInt32 right = initRight;// = ints[pairNum + 1];

                    FCi(ref left, ref right, rounfCount, isBack);

                    initLeft = ints[pairNum];
                    initRight = ints[pairNum + 1];

                    ints[pairNum] = initLeft ^ left;
                    ints[pairNum + 1] = initRight ^ right;
                }

            }

            //from int array to byte array
            var newBytes = Program.FromArrayUInt32ToArrayByte(ints);

            return newBytes;
        }
        #endregion

        protected void FCi(ref UInt32 left, ref UInt32 right, int rounfCount, bool isBack)
        {
            for (int round = 0; round < rounfCount; round++)
            {
                //take only 0-31 bit from 64 bit key
               int roundKeyNum =  isBack ? rounfCount - 1 - round : round;
               var roundKey = (UInt32)(Program.CyclRight(_key, roundKeyNum * 8) >> 32);

                //Console.WriteLine($"{(isBack? "Back: " : "Forward: ")}round {roundKeyNum}, round key num = {roundKeyNum}, round key = {roundKey}");

                var tmpXor = right ^ F(left, roundKey);
                var tmpLeft = left;

                left = round == rounfCount - 1 ? tmpLeft : tmpXor;
                right = round == rounfCount - 1? tmpXor : tmpLeft;
            }
        }

        protected UInt32 F(UInt32 left, UInt32 roundKey)
            => Program.CyclLeft(left, 9) ^ (~(Program.CyclRight(roundKey, 11) & left));
        
    }
}
