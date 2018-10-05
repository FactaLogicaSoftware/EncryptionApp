# Header specification

## Header format

* At the start of the header, it is marked by 5 null characters (byte value 0000 0000), and then the following ASCII string: "BEGIN ENCRYPTION HEADER STRING"

* The end of the header is marked by the following ASCII string "END ENCRYPTION HEADER STRING", and followed by 5 null characters (byte value 0000 0000)

* The items in the header are as followed (square brackets representing the start and end of the header, anything in braces is related to the previous option). All whitespace but simply for formatting:

```
[
-HMAC:(hash here, None)
    {
        -HASHALGO:(PBKDF2, SHA256, bcrypt),
        -ITERATIONS:(iterations here)
    }

-ENCRYPTMODE:(AES, RSA, etc)
    {
        -AESMODE:(ECB, CBC, CFB, CTR),
        -ECCMODE:(different curves fo here),
        -KEYSIZE:(int),
        -BLOCKSIZE:(int)
    }

-IV:(IV here)
]
```

## Header items

* Subitems are in the hyperlinks

| Argument                                               | Meaning                                                       | Values                                                                                                            |
| ------------------------------------------------------ |-------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| <a href="#HMAC">HMAC</a>                               | The verification hash used to confirm the file hasn't changed | 128 - 512 bit byte array (16-64 bytes)                                                                            |
| <a href="#ENCRYPTMODE">ENCRYPTMODE</a>                 | A byte representing the encryption type                       | A string in the table of <a href="#ENCRYPTMODE">ENCRYPTMODE</a> page, and the (undefined ATM -- TODO) enumeration |
| <a href="IV">IV</a>                                    | The initialization vector used to start the encryption        | 128 - 512 bit byte array (16-64 bytes)                                                                            |


### <p id="HMAC">HMAC</p>

The HMAC (Hash Message Authentication Code) is a hash that is used to verify the message hasn't been tampered with. The HMAC is the hashed value of the encrypted message. The receiver can re-hash the received message to verify the message hasn't been tampered with. **IMPORTANT: HMAC construction MUST be actual HMAC algorithm, not just hashing. See [this](https://en.wikipedia.org/wiki/HMAC#Implementation) for details ****

### <p id ="ENCRYPTMODE">ENCRYPTMODE</P>

### <p id="IV">IV</p>
