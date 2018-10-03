# Header specification

## Header format

* The items in the header are as followed (square brackets representing the start and end of the header, anything in braces is related to the previous option). Newlines and tabs are not true, but simply for formatting:

```
[
-HMAC:(hash here, None)
    { -HASHALGO:(PBKDF2, SHA256, bcrypt) }
        { -ITERATIONS:(iterations here) }
-KEYVERIFICATIONHASH:(hash here, None)
    { -HASHALGO:(PBKDF2, SHA256, bcrypt) }
        { -ITERATIONS:(iterations here) }
-ENCRYPTMODE:(AES, RSA, etc)
    {{-AESMODE:(ECB, CBC, CFB, CTR),
      -ECCMODE:(different curves fo here)}
      -KEYSIZE: (int)
      -BLOCKSIZE: (int)
    }
    { -IV:(IV here) }
]
```

## Header items

| Argument      | Meaning       | Values|
| ------------- |-------------| ----- |
| <a href="#HMAC">HMAC</a> | The verification hash used to confirm the file hasn't changed | 128 - 512 bit byte array (16-64 bytes) |
| <a href="#KEYVERIFICATIONHASH">KEYVERIFICATIONHASH</a> | A hash of the key to verify if the password is correct | 128 - 512 bit byte array (16-64 bytes) |
| <a href="#ENCRYPTMODE">ENCRYPTMODE</a> | A byte representing the encryption type | A string in the table of <a href="#ENCRYPTMODE">ENCRYPTMODE</a> page, and the (undefined ATM -- TODO) enumeration |

### <p id="HMAC">HMAC</p>

### <p id="KEYVERIFICATIONHASH">KEYVERIFICATIONHASH</p>

### <p id ="ENCRYPTMODE">ENCRYPTMODE</P>
