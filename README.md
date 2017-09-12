# spinnakerext-encryptedconfig

At Netflix, we keep encrypt all of our secrets with Metatron and
distribute them inside of the JARs deployed for our Spinnaker 
services, decrypting them in-memory only.

This repo is a mocked implementation of the codebase we use to 
handle secrets in each of our Spinnaker services.
