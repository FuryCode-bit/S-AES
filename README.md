# S-AES
A modified version of the well-known symmetric encryption algorithm, AES.

## Work

How to execute:

### Create a virtual environment and install requirements

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Encrypt some plaintext:

```shell
echo some_plaintext | python main.py enc some_key some_skey] (--time | -t) (--debug | -d)
```

### Decrypt some ciphertext:

```shell
echo ciphertext | python main.py dec some_key [some_skey] (--time | -t) (--debug | -d)
```

### Evaluate the performance in nanoseconds of both encryption and decription using AES, Custom_AES and Shuffled-AES:

```shell
echo some_plaintext | python main.py speed some_key [some_skey] (--time | -t) (--debug | -d)
```

### Encrypt some plaintext with AES-NI:

```shell
cd ciphers/AES-NI
make
echo some_plaintext | ./encrypt <aes\_key> <shuffle\_key>
```
### Decrypt some ciphertext with AES-NI:

```shell
cd ciphers/AES-NI
make
echo ciphertext | ./decrypt <aes\_key> <shuffle\_key>
```

### Evaluate the performance in nanoseconds of both encryption and decription using AES-NI:
```shell
cd ciphers/AES-NI
make
./speed
```


## References

 * [1] - https://github.com/pelisalacarta-ce/pelisalacarta-ce/blob/master/python/main-classic/lib/jscrypto.py

 * [2] - https://gist.github.com/raullenchai/2920069#file-pyaes-py

## Documentation:

 * https://www.youtube.com/watch?v=O4xNJsjtN6E

 * https://www.youtube.com/watch?v=C4ATDMIz5wc

 * https://www.youtube.com/watch?v=4zx5bM2OcvA

 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

### Articles

 * https://femionewin.medium.com/aes-encryption-with-python-step-by-step-3e3ab0b0fd6c

 * https://ieeexplore.ieee.org/document/8600161

### Tools

 * https://merri.cx/aes-sbox/

 * https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html

### Code
 
 * https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c

 * https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md

 