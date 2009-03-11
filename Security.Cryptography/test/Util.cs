// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

namespace Security.Cryptography.Test
{
    internal static class Util
    {
        /// <summary>
        ///     Utility method to compare two byte arrays for equality
        /// </summary>
        internal static bool CompareBytes(byte[] lhs, byte[] rhs)
        {
            if (lhs.Length != rhs.Length)
            {
                return false;
            }

            for (int i = 0; i < lhs.Length; ++i)
            {
                if (lhs[i] != rhs[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Convert a hex string into a byte array with one byte for every 2 hex characters.  Hex bytes
        ///     may be seperated by 0 or more whitespace characters.
        /// </summary>
        internal static byte[] HexStringToBytes(string input)
        {
            if (input == null)
                return null;

            List<byte> bytes = new List<byte>();

            foreach (string hexSubstring in input.Split(' ', '\t', '\n'))
            {
                Debug.Assert(hexSubstring.Length % 2 == 0, "hexSubstring.Length % 2 == 0");

                for (int i = 0; i < hexSubstring.Length; i += 2)
                {
                    bytes.Add(Byte.Parse(hexSubstring.Substring(i, 2), NumberStyles.HexNumber));
                }
            }

            return bytes.ToArray();
        }
    }
}
