# SkipList
The C++ implementation of an Authenticated Skip List used to generate and verify membership proofs.

This is a single-server implementation of the Authenticated Skip list, i,.e., it works on a single server and there is no use of client/server concept. However, the client/server mechanism can be very easily added.

Given a text file, it reads the file in blocks of the specified size, builds the tree and produces and verifies the membership proofs. The block size can be changed in the code.

This implementation uses openssl sha256 implementaion for hash functions. Therefore, it needs the ssl library for compilation. Moreovee, it needs c++11 support. Simply, it can be compiled as follows:

g++ SkipList.cpp -Wall -std=c++11 -lssl -lcrypto -o out_file_name
