

using System;
using System.Globalization;
using System.IO; 
using System.Text;
using System.Security.Cryptography;

public class PBKDF2Advanced
{
  byte[] buffer, salt; 
  private HMAC hmac;

  private uint iterations, blockCount;
  private int begin, end;

  //needs to be fixed
  private const int BlockSize = 20;
  //something about mode needing to be const or default
  public PBKDF2Advanced(string password, int saltSize, uint iterations/*1000*/, Type mode/* = typeof(HMACSHA256)*/) {
    if (saltSize < 0)
        throw new ArgumentOutOfRangeException("SAAAAALLLT < 0!"); 

    byte[] salt = new byte[saltSize]; 
    using (var rng = new RNGCryptoServiceProvider())
      rng.GetBytes(salt); 

    this.salt = salt; 
    this.iterations = iterations;
    if (mode.IsSubclassOf(typeof(HMAC)))
        hmac = (HMAC)Activator.CreateInstance(mode, new UTF8Encoding(false).GetBytes(password));
    else
      throw new ArgumentException("You did not supply a valid Hashing algorithm");
    Reset();
  }

  public PBKDF2Advanced(string password, byte[] salt, uint iterations/*=1000*/, Type mode/* = typeof(HMACSHA256)*/) : this (new UTF8Encoding(false).GetBytes(password), salt, iterations, mode) {}

  public PBKDF2Advanced(byte[] password, byte[] salt, uint iterations/*=1000*/, Type mode/* = typeof(HMACSHA256)*/) {
    this.salt = salt;
    this.iterations = iterations;
    if (mode.IsSubclassOf(typeof(HMAC)))
      hmac = (HMAC)Activator.CreateInstance(mode, password);
    else
      throw new ArgumentException("You did not supply a valid Hashing algorithm");
    Reset();
  } 

  public byte[] GetBytes(int byteCount)
  {
    if (byteCount <= 0)
      throw new ArgumentOutOfRangeException("byteCount is negative!"); 
    byte[] password = new byte[byteCount];

    int offset = 0; 
    int size = end - begin;

    if (size > 0)
    { 
      if (byteCount >= size)
      {
        Buffer.BlockCopy(buffer, begin, password, 0, size);
        begin = end = 0;
        offset += size; 
      }
      else
      {
        Buffer.BlockCopy(buffer, begin, password, 0, byteCount); 
        begin += byteCount; 
        return password;
      } 
    }

    System.Diagnostics.Debug.Assert(begin == 0 && end == 0, "Invalid start or end indexes in the buffer!" );

    while(offset < byteCount)
    {
      byte[] T_block = Func(); 
      int remainder = byteCount - offset; 
      
      if(remainder > BlockSize)
      {
        Buffer.BlockCopy(T_block, 0, password, offset, BlockSize); 
        offset += BlockSize;
      }
      else
      {
        Buffer.BlockCopy(T_block, 0, password, offset, remainder);
        offset += remainder; 
        Buffer.BlockCopy(T_block, remainder, buffer, begin, BlockSize - remainder);
        end += (BlockSize - remainder); 
        return password; 
      }
    } 
    return password;
  }

  public void Reset()
  {
      if (buffer != null) 
          Array.Clear(buffer, 0, buffer.Length);
      buffer = new byte[BlockSize];
      blockCount = 1;
      begin = end = 0; 
  }

  private byte[] Func()
  {
    byte[] b = BitConverter.GetBytes(blockCount); 
    byte[] littleEndianBytes = {b[3], b[2], b[1], b[0]};
    byte[] INT_block = BitConverter.IsLittleEndian ? littleEndianBytes : b;

    hmac.TransformBlock(salt, 0, salt.Length, salt, 0); 
    hmac.TransformFinalBlock(INT_block, 0, INT_block.Length);
    byte[] temporaryHash = hmac.Hash;
    hmac.Initialize(); 

    byte[] ret = temporaryHash; 
    for (int i = 2; i <= iterations; i++)
    {
      temporaryHash = hmac.ComputeHash(temporaryHash);
      for (int j = 0; j < BlockSize; j++)
      {
        ret[j] ^= temporaryHash[j]; 
      }
    } 

    // increment the blockCount count.
    blockCount++; 
    return ret;
  }
}
