# spinnaker-encrypted-config-extension

At Netflix, we keep encrypt all of our secrets with Metatron and
distribute them inside of the JARs deployed for our Spinnaker 
services, decrypting them in-memory only.

This repo is a generified implementation of our Metatron config
codebase that could be further extended to work with KMS or Vault.
