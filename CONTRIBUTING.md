# EncryptorApp

[![Build Status](https://dev.azure.com/johnkellyoxford/EncryptionApp/_apis/build/status/EncryptionApp-.NET%20Desktop-CI)](https://dev.azure.com/johnkellyoxford/EncryptionApp/_build/latest?definitionId=1) [![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Documentation:

## Directories
* `src` is the root directory for all code.
* `EncryptionApp` contains UI and logic. It is the `.exe`
* `CryptoTools` contains the encryption tools. It is a `.dll` that can be used by other applications
* `utils` contains mixed utilites
* `UnitTests` are the tests for `src` and `CryptoTools`

## Branches
* `master` is the branch the current stable release is built off
* `release` is beta/nightly versions in testing
* `dev` is working prototypes and for the majority of work
* `experimental` is for large changes that may not be functional
* `hotfix` is for quick changes to push to `master` or `release`

**Please use forks for your own work, and PR to the applicable branch**

This app is divided into 2 primary parts: The "src" folder contains the project EncryptionApp (Creative naming, we know), which compiles to the primary executable of the app and defines the UI, settings, and the interaction with the second part: The library/API. This is the EncryptionApp.Library items, currently only EncryptionApp.Library.CryptoTools, which contains (beginnings of) a variety of tools used for all types of cryptography and security, from key generation to AES encryption to HMAC authentication. Contrbuting to either project should conform to standard style guidelines and good commenting. 

An extremely important part of the CryptoTools library is the `CryptographicInfo` object. This object defines a set of values about a ciphertext, which allows it to be decrypted (provided the other side has any necessary keys) easily by the same software without any manual setting configurations. It allows a variety of encryption algorithms, key derivation algorithms, and HMAC authentication systems to be used without needing to explicitly communicate them. Using a `CryptographicInfo` object to write is very simple - set the values and call the necessary function, but reading one requires knowledge of reflection to allow instantiation of classes from type names. 

Simple encryption and decryption systems will be defines as CryptoManagers, which inherit from the CryptoManager class (TODO) and implement certain interfaces to allow for polymorphism after instantiation from type reflection. 

Contributing to the UI should keep a simplistic style, not block any threads, and it should be explicitly documented whether you are changing aesthetics or logic.
At the moment the UI is very basic and needs to be improved in user interaction and value validation. There is a significant update to it in the works.
