package com.cx.restclient.sca.utils;

import org.apache.tools.ant.DirectoryScanner;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class FingerprintCollector {

    private final SignatureCalculator sha1SignatureCalculator;
    private final Logger log;

    public FingerprintCollector(Logger log){
        this.log = log;
        sha1SignatureCalculator = new Sha1SignatureCalculator();
    }

    public CxSCAScanFingerprints collectFingerprints(String baseDir,
                                                     String[] filterIncludePatterns,
                                                     String[] filterExcludePatterns) {
        log.info(String.format("Started fingerprint collection on %s", baseDir));

        CxSCAScanFingerprints scanFingerprints = new CxSCAScanFingerprints();
        DirectoryScanner ds = createDirectoryScanner(new File(baseDir), filterIncludePatterns, filterExcludePatterns);
        ds.setFollowSymlinks(true);
        ds.scan();


        for (String filePath : ds.getIncludedFiles()) {
            Path fullFilePath = Paths.get(baseDir, filePath);
            try (FileInputStream fileInputStream = new FileInputStream(new File(fullFilePath.toString()))) {


                CxSCAFileFingerprints fingerprints = new CxSCAFileFingerprints(fullFilePath.toString(), Files.size(fullFilePath));

                fingerprints.addFileSignature(sha1SignatureCalculator.calculateSignature(fileInputStream));

                scanFingerprints.addFileFingerprints(fingerprints);
            } catch (IOException e) {
                log.error(String.format("Failed calculating file signature: %s",fullFilePath.toString() ), e);
            }
        }
        scanFingerprints.setTime(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        return scanFingerprints;

    }

    private static DirectoryScanner createDirectoryScanner(File baseDir, String[] filterIncludePatterns, String[] filterExcludePatterns) {
        DirectoryScanner ds = new DirectoryScanner();
        ds.setBasedir(baseDir);
        ds.setCaseSensitive(false);
        ds.setFollowSymlinks(false);
        ds.setErrorOnMissingDir(false);

        if (filterIncludePatterns != null && filterIncludePatterns.length > 0) {
            ds.setIncludes(filterIncludePatterns);
        }

        if (filterExcludePatterns != null && filterExcludePatterns.length > 0) {
            ds.setExcludes(filterExcludePatterns);
        }

        return ds;
    }


}
