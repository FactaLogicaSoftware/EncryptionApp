# Header specification

## Header format

* At the start of the header, it is marked by 5 null characters (byte value 0000 0000), and then the following ASCII string: "BEGIN ENCRYPTION HEADER STRING"

* The end of the header is marked by the following ASCII string "END ENCRYPTION HEADER STRING", and followed by 5 null characters (byte value 0000 0000)

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
    { -AESMODE:(ECB, CBC, CFB, CTR) }
    { -IV:(IV here) }
-KEYSIZE:(int here)
]
```

## Header items

| Argument      | Meaning       | Values|
| ------------- |-------------| ----- |
| [HMAC](#HMAC) | The verification hash used to confirm the file hasn't changed | 128 - 512 bit byte array (16-64 bytes) |
| [KEYVERIFICATIONHASH](#KEYVERIFICATIONHASH) | A hash of the key to verify if the password is correct | 128 - 512 bit byte array (16-64 bytes) |
| [ENCRYPTMODE](#ENCRYPTMODE) | A string representing the encryption type | A string in the table of [ENCRYPTMODE](#ENCRYPTMODE) page |

### HMAC

### KEYVERIFICATIONHASH
