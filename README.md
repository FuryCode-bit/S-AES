<!-- Project S-AES: https://github.com/FuryCode-bit/S-AES -->
<a name="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Stargazers][stars-shield]][stars-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/FuryCode-bit/S-AES">
    <img src="readme/ua.png" alt="Logo" height="80">
  </a>

  <h3 align="center">S-AES: Shuffled AES Encryption</h3>

  <p align="center"> A modified version of the well-known symmetric encryption algorithm, AES. 
    <br />
    <a href="https://github.com/FuryCode-bit/S-AES"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <!-- <a href="https://github.com/FuryCode-bit/S-AES">View Demo</a> -->
    ·
    <a href="https://github.com/FuryCode-bit/S-AES/issues">Report Bug</a>
    <!-- ·
    <a href="https://github.com/FuryCode-bit/S-AES/issues">Request Feature</a> -->
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project

![Product Name Screen Shot][project-screenshot]

### Overview

S-AES (Shuffled AES) is a modified version of the well-known symmetric encryption algorithm, AES (Advanced Encryption Standard). This project explores how to shuffle the S-Box used in the AES algorithm to potentially enhance or modify its encryption process, while maintaining the core principles of Rijndael, the algorithm on which AES is based.

## Background

Rijndael, the algorithm that became AES, is highly flexible. It allows a variety of data block sizes and key sizes, with ranges from 128 to 256 bits (in 16-bit increments). One notable feature of Rijndael’s design is its S-Box, a key component for security. However, the Rijndael authors state that this S-Box can be replaced with others, without compromising the security of the algorithm. This project explores the concept of shuffling the S-Box in AES for a customized encryption method, known as Shuffled AES.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

### Execution

How to execute:

#### Create a virtual environment and install requirements

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

#### Encrypt some plaintext:

```shell
echo some_plaintext | python main.py enc some_key some_skey] (--time | -t) (--debug | -d)
```

#### Decrypt some ciphertext:

```shell
echo ciphertext | python main.py dec some_key [some_skey] (--time | -t) (--debug | -d)
```

#### Evaluate the performance in nanoseconds of both encryption and decription using AES, Custom_AES and Shuffled-AES:

```shell
echo some_plaintext | python main.py speed some_key [some_skey] (--time | -t) (--debug | -d)
```

#### Encrypt some plaintext with AES-NI:

```shell
cd ciphers/AES-NI
make
echo some_plaintext | ./encrypt <aes\_key> <shuffle\_key>
```
#### Decrypt some ciphertext with AES-NI:

```shell
cd ciphers/AES-NI
make
echo ciphertext | ./decrypt <aes\_key> <shuffle\_key>
```

#### Evaluate the performance in nanoseconds of both encryption and decription using AES-NI:
```shell
cd ciphers/AES-NI
make
./speed
```

### References

 * [1] - https://github.com/pelisalacarta-ce/pelisalacarta-ce/blob/master/python/main-classic/lib/jscrypto.py

 * [2] - https://gist.github.com/raullenchai/2920069#file-pyaes-py

### Documentation:

 * https://www.youtube.com/watch?v=O4xNJsjtN6E

 * https://www.youtube.com/watch?v=C4ATDMIz5wc

 * https://www.youtube.com/watch?v=4zx5bM2OcvA

 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

#### Articles

 * https://femionewin.medium.com/aes-encryption-with-python-step-by-step-3e3ab0b0fd6c

 * https://ieeexplore.ieee.org/document/8600161

#### Tools

 * https://merri.cx/aes-sbox/

 * https://formaestudio.fcom/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html

#### Code
 
 * https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c

 * https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- Issues -->
## Issues

See the [open issues](https://github.com/FuryCode-bit/S-AES/issues) for a full list of proposed features (and known issues).

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->

[contributors-shield]: https://img.shields.io/github/contributors/FuryCode-bit/S-AES.svg?style=for-the-badge
[contributors-url]: https://github.com/FuryCode-bit/S-AES/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/FuryCode-bit/S-AES.svg?style=for-the-badge
[forks-url]: https://github.com/FuryCode-bit/S-AES/network/members
[stars-shield]: https://img.shields.io/github/stars/FuryCode-bit/S-AES.svg?style=for-the-badge
[stars-url]: https://github.com/FuryCode-bit/S-AES/stargazers
[issues-shield]: https://img.shields.io/github/issues/FuryCode-bit/S-AES.svg?style=for-the-badge
[issues-url]: https://github.com/FuryCode-bit/S-AES/issues
[license-shield]: https://img.shields.io/github/license/FuryCode-bit/S-AES.svg?style=for-the-badge
[license-url]: https://github.com/FuryCode-bit/S-AES/blob/master/LICENSE

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/bernardeswebdev

[project-screenshot]: readme/saes.png
