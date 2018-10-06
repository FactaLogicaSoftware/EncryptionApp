

# EncryptorAppVS



## Documentation:

## Right now
* Build header spec
* Input sanitisation and error handling

## To do
* Let user know when the decryption has not taken place due to incorrect pwd
* RSA
* Incorporate microsoft data protector
* .crypt header files
* Create documentation and tutorial
* create a microsoft installer application with certificates --> trust

## Updates
* Add error handling if encryption/decryption fails

## Directories
* `src` contains UI and logic. It is the `.exe`
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
