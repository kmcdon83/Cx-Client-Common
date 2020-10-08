//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.cx.restclient.sast.utils.zip;


import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.zip.ZipEntry;
import org.apache.tools.zip.ZipOutputStream;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Zipper {

    private final Logger log;

    public Zipper(Logger log) {
        this.log = log;
    }

    public void zip(File baseDir, String[] filterIncludePatterns, String[] filterExcludePatterns, OutputStream outputStream, long maxZipSize, ZipListener listener) throws IOException {
        assert baseDir != null : "baseDir must not be null";
        assert outputStream != null : "outputStream must not be null";

        filterIncludePatterns = ArrayUtils.contains(filterIncludePatterns, "**/*") ? filterIncludePatterns : ArrayUtils.add(filterIncludePatterns, "**/*");
        DirectoryScanner ds = createDirectoryScanner(baseDir, filterIncludePatterns, filterExcludePatterns);
        ds.scan();
        printDebug(ds);
        if (ds.getIncludedFiles().length == 0) {
            outputStream.close();
            log.info("No files to zip");
            throw new NoFilesToZip();
        }
        zipFile(baseDir, ds.getIncludedFiles(), outputStream, maxZipSize, listener);
    }

    private synchronized void zipFile(File baseDir, String[] files, OutputStream outputStream, long maxZipSize, ZipListener listener) throws IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.setEncoding("UTF8");
            long compressedSize = 0;
            final double AVERAGE_ZIP_COMPRESSION_RATIO = 4.0;

            for (String fileName : files) {
                log.debug("Adding file to zip: " + fileName);

                File file = new File(baseDir, fileName);
                if (!file.canRead()) {
                    log.warn("Skipping unreadable file: " + file);
                    continue;
                }

                if (maxZipSize > 0 && compressedSize + (file.length() / AVERAGE_ZIP_COMPRESSION_RATIO) > maxZipSize) {
                    log.info("Maximum zip file size reached. Zip size: " + compressedSize + " bytes Limit: " + maxZipSize + " bytes");
                    zipOutputStream.close();
                    throw new MaxZipSizeReached(compressedSize, maxZipSize);
                }

                ZipEntry zipEntry = new ZipEntry(fileName);
                zipOutputStream.putNextEntry(zipEntry);

                FileInputStream fileInputStream = new FileInputStream(file);
                IOUtils.copy(fileInputStream, zipOutputStream);
                fileInputStream.close();
                zipOutputStream.closeEntry();
                compressedSize += zipEntry.getCompressedSize();

                if (listener != null) {
                    listener.updateProgress(fileName, compressedSize);
                }
            }
        }
    }

    private DirectoryScanner createDirectoryScanner(File baseDir, String[] filterIncludePatterns, String[] filterExcludePatterns) {
        DirectoryScanner ds = new DirectoryScanner();
        ds.setBasedir(baseDir);
        ds.setCaseSensitive(false);
        ds.setFollowSymlinks(true);
        ds.setErrorOnMissingDir(false);
        if (filterIncludePatterns != null && filterIncludePatterns.length > 0) {
            ds.setIncludes(filterIncludePatterns);
        }

        if (filterExcludePatterns != null && filterExcludePatterns.length > 0) {
            ds.setExcludes(filterExcludePatterns);
        }

        return ds;
    }

    private void printDebug(DirectoryScanner ds) {
        if (!log.isDebugEnabled()) {
            return;
        }

        log.debug("Base Directory: " + ds.getBasedir());

        for (String file : ds.getIncludedFiles()) {
            log.debug("Included: " + file);
        }

        for (String file : ds.getExcludedFiles()) {
            log.debug("Excluded File: " + file);
        }

        for (String file : ds.getExcludedDirectories()) {
            log.debug("Excluded Dir: " + file);
        }

        for (String file : ds.getNotFollowedSymlinks()) {
            log.debug("Not followed symbolic link: " + file);
        }
    }

    public static class NoFilesToZip extends IOException {
        public NoFilesToZip() {
            super("No files to zip");
        }
    }

    public static class MaxZipSizeReached extends IOException {
        private long compressedSize;
        private long maxZipSize;

        public MaxZipSizeReached(long compressedSize, long maxZipSize) {
            super("Zip compressed size reached a limit of " + maxZipSize + " bytes");
        }

        public long getCompressedSize() {
            return this.compressedSize;
        }

        public long getMaxZipSize() {
            return this.maxZipSize;
        }
    }

}
