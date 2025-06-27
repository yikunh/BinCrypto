## BinCrypto: Binary Cryptographic Function Identification via Similarity Analysis with Path-insensitive Emulation

### Introduction
*	Here is the artifact of BinCrypto, which aims to identify the cryptographic function in the target binary file via similarity analysis.
*	It is provided as a Docker image based on Linux, containing the sample binaries and compiled executables of BinCrypto’s prototype.
*	Since it may take several hours to analyze complex binaries, the artifact uses relatively simpler samples adopted in the paper to demonstrate its functionality. The file tree of the artifact is:
```
|--- binCrypto/
|    |--- bin/                              # the directory of binaries
|    |    |--- x64_libcl347_gcc114_O0
|    |    |--- x64_libcl347_gcc114_O3
|    |    |--- ...
|    |--- data/                             # the directory of binaries' preprocess data
|    |    |--- x64_libcl347_gcc114_O0/
|    |    |--- x64_libcl347_gcc114_O3/
|    |    |--- ...
|    |--- scripts/                          # the directory of Python scripts
|    |    |--- emulate_binary.py            # to emulate a binary for code features
|    |    |--- compare_binaries.py          # to compare binaries for similarity scores
|    |--- signatures/                       # the directory of extracted code features
|    |    |--- x64_libcl347_gcc114_O0/
|    |    |--- x64_libcl347_gcc114_O3/
|    |    |--- ...
|    |--- output/                           # the directory of similarity scores in details
|    |--- executables/                      # the directory of executables to emulate and compare binaries
|    |    |--- emulation                    # to generally emulate one binary for code features
|    |    |--- emulation_cross              # to emulate one binary for cross-library analysis
|    |    |--- comparison                   # to generally compare two binaries for similarity scores
|    |    |--- comparison_cross             # to compare binaries for cross-library analysis
|    |--- random.txt                        # the pre-defined random input values for emulation
|    |--- Dockerfile                        # the configuration file for Docker
```


### Hardware Dependencies
The basic configuration of the docker image:
*	Image Size: 8.58 GB (889.33 MB in compression)
*	Memory Usage: >= 6.8 GB


### Getting Started Guide
*	Please make sure [**Docker**](https://docs.docker.com/get-started/get-docker/) has been installed on your system.
*	Pull down the Docker image and run it.
	```bash
	$ docker pull ruixiongh/bincrypto:latest
	$ docker run --name bincrypto -it ruixiongh/bincrypto:latest
	```
*	Then, it is under the root path of the prototype.

### Step by Step Instructions

#### 1. Reproduction with Sample Binaries
*	The preprocessing data is generated via [IDA Pro v7.7](https://hex-rays.com/blog/ida-7-7-released) with according [IDAPython](https://github.com/idapython) for automation.
*	Since the tool is not open, the data is prepared beforehand and placed under `(root)/data` for every function of each binary. For a function **func**, its data includes:
	*	**func-dumpBBOffset**: the address of each basic block
	*	**func-dumpBBandPredsOffset**: the addresses of predecessors for each basic block
	*	**func-dumpCheckpoint**:  the addresses of basic blocks that has more than two predecessors
	*	**func-dumpOffset.txt**:  the start address of the function
	*	**func-dumpPrototype**: the parameter list of func
	*	**func-instAddrList**:  the addresses of basic blocks in the breadth-first search order
	*	**func-jumpBlock**: the addresses of basic blocks ending with a conditional jump
	*	**func-loopBackEdge**:  the source and destination addresses of loops' backedges
	*	**func-negOffsetInMemoryOp**: the absolute values of offsets which are represented in two's complement
*	The sample binaries are presented unstripped to enhance the readability of the results, while BinCrypto **does not** rely on the symbol and debug information in any way.

##### 1.1 Basic Performance
*	Sample binaries: **x64_libcl347_gcc114_O3** and **x64_libcl347_gcc114_O0**
	*	**x64_libcl347_gcc114_O3**:  cryptolib v3.4.7 which is compiled with GCC v11.4.0 **-O3**
	*	**x64_libcl347_gcc114_O0**:  cryptolib v3.4.7 which is compiled with GCC v11.4.0 **-O0**
*	**Step 1**: Emulation to extract function signatures
	```bash
	# time consumption: around 200 seconds in total
	$ python3 scripts/emulate_binary.py --basic x64_libcl347_gcc114_O3 --general
	$ python3 scripts/emulate_binary.py --basic x64_libcl347_gcc114_O0 --general
	```
	*	In CLI, the time of emulation is displayed after finishing the process.
	*	The signatures are placed in the directories named after the corresponding binary.
		*	`(root)/signatures/x64_libcl347_gcc114_O3/`
		*	`(root)/signatures/x64_libcl347_gcc114_O0/`
	*	In each directory, each file stores the signature sequence of that function.
*	**Step 2**: Comparison for similarity scores
    ```bash
	# time consumption: around 15 seconds
	$ python3 scripts/compare_binaries.py --target x64_libcl347_gcc114_O3 --reference x64_libcl347_gcc114_O0
	```
	*	Compare each function signature of the TAR to those of the REF.
		*	REF: **x64_libcl347_gcc114_O0**
		*	TAR: **x64_libcl347_gcc114_O3**
	*	When finished, the overview of the analysis results are displayed in the CLI.
		*	**Correct Number** = 924 (no. of TAR functions identified correctly)
		*	**Total Number** = 1194 (no. of TAR functions)
		*	**Recall@1** = 0.773869 (ratio of TAR functions achieve the correct match)
		*	**Single Match Ratio** 0.901515 (the discernment of a method)
		*	**Process Time** = 15.181 (the time, in seconds, taken for the analysis)
		*	 The results are considered to be consistent with those in **Table 3** on **Page 17** of the paper.
		*	It is noteworthy that the results are not exactly the same as those in the paper because the emulation is performed with random values as the input.
	*	Detailed results are in: `(root)/output/x64_libcl347_gcc114_O3_vs_x64_libcl347_gcc114_O0/`
		*	**log/**: the directory that stores the similarity score of every REF function compared to the TAR function, one `.txt` file per TAR function
			*	Each file is named as that of a TAR function.
			*	Each line of a file is a REF function and the similarity score with the TAR function.
			*	For example, 
			    ```bash
			    # the similarity scores to compare idea_encrypto of x64_libcl347_gcc114_O3 to all functions of x64_libcl347_gcc114_O0
			    # the results are sorted in the descending order according to the scores
			    # finally, the reference function idea_encrypt is correctly matched with the highest score of 0.478273
			    $ cat ./output/x64_libcl347_gcc114_O3_vs_x64_libcl347_gcc114_O0/log/idea_encrypt.txt | head
			     idea_encrypt 	 score : 0.478273.
			     appendContentListItem 	 score : 0.079680.
			     deleteSessionInfo 	 score : 0.077779.
			     checkMissingInfo 	 score : 0.069746.
			     copyPkiUserToCertReq 	 score : 0.062339.
			     SHA1_Final 	 score : 0.062305.
			     endTrustInfo 	 score : 0.062241.
			     ec_GFp_simple_invert 	 score : 0.061729.
			     deriveTLS12 	 score : 0.055556.
			     importPKCS1 	 score : 0.055556.
			    ```
		*	**false_positives.log**:  false positives of the analysis
		*	**result.log**: the overview of the analysis results
		*	**single_match.log**: the TAR functions achieve the single match
*	Binaries of **cryptolib** compiled with variant configurations are provided as well for other settings of similarity analysis, including:
	*	Cross Optimization Analysis
		*	REF: **x64_libcl347_clang15_O0**, TAR: **x64_libcl347_clang15_O3**
			```bash
			#CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_clang15_O0 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_clang15_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_clang15_O3 -r x64_libcl347_clang15_O0
			```
		*  REF: **x64_libcl347_icx230320_O0**, TAR: **x64_libcl347_icx230320_O3** 
		   	```bash
		   	#CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_icx230320_O0 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_icx230320_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_icx230320_O3 -r x64_libcl347_icx230320_O0
			```
	*  Cross Compiler Analysis
		*  REF: **x64_libcl347_gcc114_O3**, TAR: **x64_libcl347_clang15_O3**
		   ```bash
		   #CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_gcc114_O3 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_clang15_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_clang15_O3 -r x64_libcl347_gcc114_O3
			```
		*  REF: **x64_libcl347_gcc114_O3**, TAR: **x64_libcl347_icx230320_O3**
		   ```bash
		   #CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_gcc114_O3 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_icx230320_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_icx230320_O3 -r x64_libcl347_gcc114_O3
			```
	*  Cross Compiler and Optimization Analysis (time consumption: around 120 seconds for each pair of comparison)
		*  REF: **x64_libcl347_gcc114_O0**, TAR: **x64_libcl347_clang15_O3**
		   ```bash
		   #CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_gcc114_O0 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_clang15_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_clang15_O3 -r x64_libcl347_gcc114_O0
			```
		*  REF: **x64_libcl347_gcc114_O0**, TAR: **x64_libcl347_icx230320_O3**
		   ```bash
		   #CMD, time consumption: around 240 seconds in total
			python3 scripts/emulate_binary.py -b x64_libcl347_gcc114_O0 -g
			python3 scripts/emulate_binary.py -b x64_libcl347_icx230320_O3 -g
			python3 scripts/compare_binaries.py -t x64_libcl347_icx230320_O3 -r x64_libcl347_gcc114_O0
			```
	*  The results above are consistent with those in **Table 3** on **Page 17** of the paper.

##### 1.2 Application: Statically-Linked Library Analysis
*	Locate the statically-linked cryptographic functions.
	*	TAR: **34** cryptographic functions implemented in **x64_libcrypto111f_gcc114_O3**
		*	The crypto functions are listed in the file at `(root)/data/crypto_func_lst.out`
	*	REF: **x64_nginx1240_gcc114_O3**
	```bash
        # only process the 34 crypto functions, time consumption: within 5 seconds
        $ python3 scripts/emulate_binary.py --static x64_libcrypto111f_gcc114_O3 --crypto
        # time consumption: around 40 minutes
        $ python3 scripts/emulate_binary.py --static x64_nginx1240_gcc114_O3 --general
        # time consumption: around 15 seconds
        $ python3 scripts/compare_binaries.py --target x64_libcrypto111f_gcc114_O3 --reference x64_nginx1240_gcc114_O3
        ```
*  The results are consistent with those in **Table 5** on **Page 20** of the paper.

##### 1.3 Application: Cross-Library Analysis
*	Identify functions that implement the same cryptographic algorithms.
	*	REF: **34** cryptographic functions implemented in **x64_libcrypto111f_gcc114_O3**
		*	The crypto functions are listed in the file at `(root)/data/crypto_func_lst.out`
	*	TAR: **x64_libcl347_gcc114_O0**
    ```bash
    # only process the 34 crypto functions, time consumption: within 5 seconds
    $ python3 scripts/emulate_binary.py --cross x64_libcrypto111f_gcc114_O3 --crypto
    # time consumption: around 90 seconds
    $ python3 scripts/emulate_binary.py --cross x64_libcl347_gcc114_O0 --general
    # time consumption: around 1 second
    $ python3 scripts/compare_binaries.py --reference x64_libcrypto111f_gcc114_O3 --target x64_libcl347_gcc114_O0 --cross
    ```
*	**libcl** is found to have 6 functions which implement the same algorithms as **libcrypto**, and 4 of them are correctly identified, as indicated with the latter's function name in the brackets.
	*	MD5_Update (MD5_Update)
	*	idea_set_decrypt_key (IDEA_set_decrypt_key)
	*	idea_set_encrypt_key (IDEA_set_encrypt_key)
	*	idea_encrypt (IDEA_encrypt)
	*	aes_decrypt
	*	aes_encrypt
*	Since function symbol names vary across libraries, the detailed results can be reviewed manually using `cat`. In each case, the correct match achieves the highest score and is ranked first.
    ```bash
    # check the lists of results at (root)/output/x64_libcl347_gcc114_O0_vs_x64_libcrypto111f_gcc114_O3/log
    $ cat ./output/x64_libcl347_gcc114_O0_vs_x64_libcrypto111f_gcc114_O3/log/MD5_Update.txt | head
    $ cat ./output/x64_libcl347_gcc114_O0_vs_x64_libcrypto111f_gcc114_O3/log/idea_set_decrypt_key.txt | head
    $ cat ./output/x64_libcl347_gcc114_O0_vs_x64_libcrypto111f_gcc114_O3/log/idea_set_encrypt_key.txt | head
    $ cat ./output/x64_libcl347_gcc114_O0_vs_x64_libcrypto111f_gcc114_O3/log/idea_encrypt.txt | head
    ```
    *  The results are consistent with those in **Figure 8** on **Page 20** of the paper.

##### 1.4 Application: Obfuscated Code Analysis 
*	Obfuscator-LLVM (OLLVM) is a project provides three typical obfuscation techniques.
	*	SUB: instruction subsititution
	*	BCF: bogus control flow
	*	FLA: control flow flattening
*	Analyze binaries obfuscated with OLLVM.
	*	REF: **x64_libnettle391_gcc114_O2**
	*	TAR: **x64_libnettle391_ollvm4sub_O2**, **x64_libnettle391_ollvm4bcf_O2**, and **x64_libnettle391_ollvm4fla_O2**
	```bash
	# time consumption: around 30 seconds
	$ python3 scripts/emulate_binary.py --obfuscated x64_libnettle391_gcc114_O2 --general
	# analyze code obfuscated by SUB, time consumption: around 60 seconds
	$ python3 scripts/emulate_binary.py --obfuscated x64_libnettle391_ollvm4sub_O2 --general
	$ python3 scripts/compare_binaries.py --reference x64_libnettle391_gcc114_O2 --target x64_libnettle391_ollvm4sub_O2
	# analyze code obfuscated by BCF, time consumption: around 60 seconds
	$ python3 scripts/emulate_binary.py --obfuscated x64_libnettle391_ollvm4bcf_O2 --general
	$ python3 scripts/compare_binaries.py --reference x64_libnettle391_gcc114_O2 --target x64_libnettle391_ollvm4bcf_O2
	# analyze code obfuscated by FLA, time consumption: around 60 seconds
	$ python3 scripts/emulate_binary.py --obfuscated x64_libnettle391_ollvm4fla_O2 --general
	$ python3 scripts/compare_binaries.py --reference x64_libnettle391_gcc114_O2 --target x64_libnettle391_ollvm4fla_O2
	```
	*  The results are consistent with those in **Table 6** on **Page 21** of the paper.

##### 1.5 Application: Malware Analysis
*	Identify the cryptographic functions in malware, to find the function in **REVil** that is most similar to *AES_encrypt* of **libcrypto**.
	*	TAR: **x64_libcrypto111f_gcc114_O0**
	*	REF: [**REvil**](https://en.wikipedia.org/wiki/REvil), a ransomware adopts AES for encryption
	```bash
	# time consumption: within 180 seconds in total
	$ python3 scripts/emulate_binary.py --malicious x64_libcrypto111f_gcc114_O0 --crypto
	$ python3 scripts/emulate_binary.py --malicious revil --general
	$ python3 scripts/compare_binaries.py --target x64_libcrypto111f_gcc114_O0 --reference revil
	```
*	*AES_encrypt* from **libcrypto** is correctly matched to the one at `0x40f35e` in REvil with the highest score of the results (listed on the first line).
	```bash
	# check the AES function found in revil
	$ cat ./output/x64_libcrypto111f_gcc114_O0_vs_revil/log/AES_encrypt.txt | head
	```
	*  The result is consistent with that in **Table 7** on **Page 22** of the paper.

### Reusability Guide
*	The core parts of the artifact are **binary emulation** for code features and **binary comparison** for similarity scores. All the above reproductions are primarily conducted around the two components of the prototype.
	*	Thus, as indicated in Section 1.1, all the reproductions are performed in two steps, i.e., emulation and comparison, which are the same for other use cases.
	*	In the artifact, only a subset of the sample binaries from the paper is provided, due to the high time and space overhead required to analyze complex samples.
		*	For example, it would take over 1 hour to analyze **libcrypto**.
		*	Over 3 hours are needed to handle obfuscated **libcrypto**, and at least 300 GB memory is required to perform the comparison for the current prototype.
*	To adopt the artifact to new use cases, users need to prepare the preprocess data for the binaries under analysis. The current prototype relies on IDA Pro, which is a commercial tool, to disassemble the binary code and generate the required data. According to the description in Section 1, users can also obtain the data with other disassemblers.
