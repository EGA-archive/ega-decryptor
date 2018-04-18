# EGA Decryption Client

This is Java-based a decryption tool for EGA '.cip' files.

This code is provided as-is. It is has limited supported by the EGA. 

## Getting Started

Running the tool from the command line: "java -jar EgaDecryptor.jar [options]"

```
Usage: <main class> [options]
  Options:
    --bits
      Encryption Strength: 256 or 128 bits.
      Default: 128
    --debug
      Print Some Debug Information
    --file
      Specify a file or a folder containing '.cip' files.
    --help
      Print Help
    --keep
      Keep the encrypted copy of the file.
      Default: true
    --key
      Specify the decryption key.
    --keyfile
      Specify a file containing the decryption key.
    --output-folder
      Specify an output folder for decrypted files (default: .).
    --threads
      Number of parallel threads to use (default: # of CPU cores).
      Default: 0
    --version
      Print Version Number
```


### Installing

A step by step series of examples that tell you have to get a development env running

The repository contains pre-compiled jar files with the client in the 'store' directory. To build it on your local machine, run

```
ant jar
```

This will produce a set of files to run the client in the /dist folder. To create a version with all dependencies packaged into a single jar file, run

```
ant jar package-for-store
```

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE.md](LICENSE.md) file for details

