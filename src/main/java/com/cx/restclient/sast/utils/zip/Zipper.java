//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.cx.restclient.sast.utils.zip;


import org.apache.commons.io.IOUtils;
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

        DirectoryScanner ds = this.createDirectoryScanner(baseDir, filterIncludePatterns, filterExcludePatterns);
        ds.setFollowSymlinks(true);
        ds.scan();
       // this.printDebug(ds);
        if (ds.getIncludedFiles().length == 0) {
            outputStream.close();
            log.info("No files to zip");
            throw new Zipper.NoFilesToZip();
        } else {
            this.zipFile(baseDir, ds.getIncludedFiles(), outputStream, maxZipSize, listener);
        }
    }

    private void zipFile(File baseDir, String[] files, OutputStream outputStream, long maxZipSize, ZipListener listener) throws IOException {
        ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream);
        zipOutputStream.setEncoding("UTF8");
        long compressedSize = 0L;
        double AVERAGE_ZIP_COMPRESSION_RATIO = 4.0D;
        String[] arr$ = files;
        int len$ = files.length;

        for (int i$ = 0; i$ < len$; ++i$) {
            String fileName = arr$[i$];
          //  log.debug("Adding file to zip: " + fileName);
            File file = new File(baseDir, fileName);
            if (!file.canRead()) {
                log.warn("Skipping unreadable file: " + file);
            } else {
                if (maxZipSize > 0L && (double) compressedSize + (double) file.length() / 4.0D > (double) maxZipSize) {
                    log.info("Maximum zip file size reached. Zip size: " + compressedSize + " bytes Limit: " + maxZipSize + " bytes");
                    zipOutputStream.close();
                    throw new Zipper.MaxZipSizeReached(compressedSize, maxZipSize);
                }

                if (listener != null) {
                    listener.updateProgress(fileName, compressedSize);
                }

                ZipEntry zipEntry = new ZipEntry(fileName);
                zipOutputStream.putNextEntry(zipEntry);
                FileInputStream fileInputStream = new FileInputStream(file);
                IOUtils.copy(fileInputStream, zipOutputStream);
                fileInputStream.close();
                zipOutputStream.closeEntry();
                compressedSize += zipEntry.getCompressedSize();
            }
        }

        zipOutputStream.close();
    }

    private DirectoryScanner createDirectoryScanner(File baseDir, String[] filterIncludePatterns, String[] filterExcludePatterns) {
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

    private void printDebug(DirectoryScanner ds) {
        if (log.isDebugEnabled()) {
            log.debug("Base Directory: " + ds.getBasedir());
            String[] arr$ = ds.getIncludedFiles();
            int len$ = arr$.length;

            int i$;
            String file;
            for (i$ = 0; i$ < len$; ++i$) {
                file = arr$[i$];
                log.debug("Included: " + file);
            }

            arr$ = ds.getExcludedFiles();
            len$ = arr$.length;

            for (i$ = 0; i$ < len$; ++i$) {
                file = arr$[i$];
                log.debug("Excluded File: " + file);
            }

            arr$ = ds.getExcludedDirectories();
            len$ = arr$.length;

            for (i$ = 0; i$ < len$; ++i$) {
                file = arr$[i$];
                log.debug("Excluded Dir: " + file);
            }

            arr$ = ds.getNotFollowedSymlinks();
            len$ = arr$.length;

            for (i$ = 0; i$ < len$; ++i$) {
                file = arr$[i$];
                log.debug("Not followed symbolic link: " + file);
            }

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
