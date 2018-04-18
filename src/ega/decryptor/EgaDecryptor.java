/*
 * Copyright 2018 ELIXIR EGA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ega.decryptor;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 *
 * @author asenf
 */
public class EgaDecryptor {
    private static final int VERSION_MAJOR = 1;
    private static final int VERSION_MINOR = 0;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        /*
         * Variables
         */
        
        String[] filePath = null; // Files to be decrypted
        String outputPath = null; // Destination of Output
        boolean keep = true; // Keep or Delete file after decryption
        int bits = 128; // AES strength or encrypted files
        String decryptionKey = null; // What it says on the tin
        int nThreads = 1; // Number of parallel threads for decryption
        boolean debug = false; // Extra output information
        
        /*
         * Parameter Handling
         */
        
        Params params = new Params();
        JCommander jc = new JCommander(params);
        jc.parse(args);
        
        // Print Help
        if (params.help) {
            jc.usage();
            return;
        }
        // Print Version
        if (params.version) {
            System.out.println("Version: " + VERSION_MAJOR + "." + VERSION_MINOR);
            return;
        }
        
        /*
         * Validate Parameters
         */
        
        // Debug
        debug = params.debug;
        // AES Key Strength
        bits = params.aesBits;
        if (bits!=128 && bits!=256) {
            System.out.println("Valid choices are '128' or '256'");
            return;
        }
        if (debug) System.out.println("Source File AES-" + bits);
        // Decryption Key
        if (params.keyKey!=null && params.keyKey.length()>0) {
            decryptionKey = params.keyKey;
        } else if (params.keyFile!=null && params.keyFile.length()>0) {
            try {
                BufferedReader decryptionKeyFile = new BufferedReader(new FileReader(params.keyFile));
                decryptionKey = decryptionKeyFile.readLine().trim();
            } catch (FileNotFoundException ex) {
                System.out.println("Error accessing Key File: " + params.keyFile);
                System.out.println(ex.toString());
                return;
            } catch (IOException ex) {
                System.out.println("Error reading from Key File: " + params.keyFile);
                System.out.println(ex.toString());
                return;
            }
        } else {
            System.out.println("Decryption Key must be specified.");
            jc.usage();
            return;
        }
        if (debug) System.out.println("Key " + decryptionKey);
        // Output Destination - exists and is writeable 
        if (params.outputPath!=null && params.outputPath.length()>0) {
            File outputDestination = new File(params.outputPath);
            try {
                if (outputDestination.exists() && outputDestination.isDirectory()) {
                    outputPath = outputDestination.getCanonicalPath();
                } else {
                    outputPath = Paths.get(".").toAbsolutePath().normalize().toString();
                }
                if (!(new File(outputPath).canWrite())) {
                    System.out.println("Can't write to directoty: " + outputPath);
                    return;
                } else {
                    System.out.println("Using output directoty: " + outputPath);
                }
            } catch (IOException ex) {
                System.out.println("Error accessing output directory.");
                jc.usage();
                return;
            }
        } else {
            outputPath = Paths.get(".").toAbsolutePath().normalize().toString();            
        }
        if (debug) System.out.println("Destination path: " + outputPath);
        // Input File(s)        
        try {
            ArrayList<String> sourceFiles = new ArrayList<>();
            if (params.filePath!=null && params.filePath.length()>0) { // path specified
                File path = new File(params.filePath);
                if (path.isDirectory()) { // a directory
                    File[] listOfFiles = path.listFiles();
                    for (int i=0; i<listOfFiles.length; i++) {
                        String onePath = path.getCanonicalPath();
                        if (onePath.toLowerCase().endsWith(".cip")) {
                            sourceFiles.add(onePath);
                            if (debug) System.out.println("Decrypting " + onePath);
                        }
                    }
                } else  { // A single file
                    String onePath = path.getCanonicalPath();
                    if (onePath.toLowerCase().endsWith(".cip")) {
                        sourceFiles.add(onePath);
                        if (debug) System.out.println("Decrypting " + onePath);
                    } else {
                        System.out.println("Source must be an encrypted file ending in '.cip'");
                        return;
                    }
                }
            } else { // the local directory
                String localPath = Paths.get(".").toAbsolutePath().normalize().toString();
                File localDir = new File(localPath);
                File[] listOfFiles = localDir.listFiles();
                for (int i=0; i<listOfFiles.length; i++) {
                    String onePath = localDir.getCanonicalPath();
                    if (onePath.toLowerCase().endsWith(".cip")) {
                        sourceFiles.add(onePath);
                        if (debug) System.out.println("Decrypting " + onePath);
                    }
                }
            }
            if (sourceFiles.size() > 0) {
                filePath = new String[sourceFiles.size()];
                filePath = sourceFiles.toArray(filePath);
            } else {
                System.out.println("No '.cip' files have been found at the specified location.");
                return;
            }
        } catch (IOException ex) {
            System.out.println("Error accessing input file or directory: " + params.filePath);
            jc.usage();
            return;
        }
        // keep?
        keep = params.keep;
        if (debug) System.out.println("Keeo encrypted files after decryption? " + keep);
        // Threads - only of more than one file specified
        if (filePath.length>0) {
            if (params.threads > 1) {
                nThreads = params.threads;
            } else {
                nThreads = Runtime.getRuntime().availableProcessors();
            }
        } else {
            nThreads = 1;
        }
        if (debug) System.out.println("Number of threads: " + nThreads);
        
        /*
         * Main program - decrypt
         */
        if (debug) System.out.println("Parameter Validation Passed!");

        ArrayList<Future<?>> results = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(nThreads);

        try {
            for (int i=0; i<filePath.length; i++) {
                InputStream in = new FileInputStream(filePath[i]);
                String filename = filePath[i].contains("/") ?
                        filePath[i].substring(filePath[i].lastIndexOf("/")) :
                        filePath[i];
                filename = filename.substring(0, filename.length()-4);
                String outFilepath = outputPath + filename;
                OutputStream out = new FileOutputStream(outFilepath);

                EgaCipherStream x = new EgaCipherStream(in, out, 65535, decryptionKey.toCharArray(), false, bits);
                Future<?> submit = executor.submit(x);
                results.add(submit);
            }
        } catch(FileNotFoundException ex) {
            System.out.println("Error accessing one of the input files.");
            System.out.println(ex.toString());
            return;
        }
        
        long dt = System.currentTimeMillis();
        System.out.println("Wait for Completion");
        try {
            boolean wait = true;
            while (wait) {
                Thread.sleep(150);
                wait = false;
                for (int j=0; j<results.size(); j++) {
                    if (!results.get(j).isDone())
                        wait = true;
                }
            }
            dt = System.currentTimeMillis() - dt;
        } catch (InterruptedException ex) {
            // ;
        }
        
        // Shut down executor service
        executor.shutdown();

        // Delete source files at the end, if selected
        if (!keep) {
            for (int i=0; i<filePath.length; i++) {
                File f = new File(filePath[i]);
                f.delete();
            }
        }
        
        // Done
        System.out.println("Done");
        System.out.println(dt + " ms decrypting " + filePath.length + " file(s).");
        return;
    }
    
    /*
     * Parameters 
     */
    @Parameters
    static class Params {
        @Parameter(names = {"--bits"}, description = "Encryption Strength: 256 or 128 bits.")
        int aesBits = 128;

        @Parameter(names = {"--file"}, description = "Specify a file or a folder containing '.cip' files.")
        String filePath;

        @Parameter(names = {"--key"}, description = "Specify the decryption key.")
        String keyKey;

        @Parameter(names = {"--keyfile"}, description = "Specify a file containing the decryption key.")
        String keyFile;
        
        @Parameter(names = {"--threads"}, description = "Number of parallel threads to use (default: # of CPU cores).")
        int threads = 0;

        @Parameter(names = {"--keep"}, description = "Keep the encrypted copy of the file.")
        Boolean keep = true;

        @Parameter(names = {"--output-folder"}, description = "Specify an output folder for decrypted files (default: .).")
        String outputPath;

        @Parameter(names = {"--help"}, description = "Print Help", help = true)
        boolean help = false;

        @Parameter(names = {"--version"}, description = "Print Version Number", help = true)
        boolean version = false;

        @Parameter(names = {"--debug"}, description = "Print Some Debug Information", help = true)
        boolean debug = false;
    }

}
