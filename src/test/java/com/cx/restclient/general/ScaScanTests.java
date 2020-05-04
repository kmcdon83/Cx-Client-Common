package com.cx.restclient.general;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.dto.DependencyScannerType;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sca.dto.*;
import com.cx.utility.TestingUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

@Slf4j
public class ScaScanTests extends CommonClientTest {

    // Storing the test project as an archive to avoid cluttering the current project
    // and also to prevent false positives during a vulnerability scan of the current project.
    public static final String PACKED_SOURCES_TO_SCAN = "sources-to-scan.zip";

    @Test
    public void scan_localDirUpload() throws IOException, CxClientException {
        CxScanConfig config = initScaConfig();
        config.setOsaThresholdsEnabled(true);
        config.getScaConfig().setSourceLocationType(SourceLocationType.LOCAL_DIRECTORY);

        Path sourcesDir = null;
        try {
            sourcesDir = extractTestProjectFromResources();
            config.setSourceDir(sourcesDir.toString());

            DependencyScanResults scanResults = scanUsing(config);

            checkCommonAssertions(scanResults);
            checkDirectoryUploadAssertions(scanResults);
        } finally {
            deleteDir(sourcesDir);
        }
    }

    private void checkDirectoryUploadAssertions(DependencyScanResults scanResults) {
        if (scanResults == null ||
                scanResults.getScaResults() == null ||
                scanResults.getScaResults().getSummary() == null) {
            Assert.fail("Unable to find summary.");
        }

        SCASummaryResults summary = scanResults.getScaResults().getSummary();
        Assert.assertTrue("SCA hasn't found any packages.", summary.getTotalPackages() > 0);

        boolean anyVulnerabilitiesDetected = summary.getHighVulnerabilityCount() > 0 ||
                summary.getMediumVulnerabilityCount() > 0 ||
                summary.getLowVulnerabilityCount() > 0;
        Assert.assertTrue("No vulnerabilities were detected.", anyVulnerabilitiesDetected);
    }

    @Test
    public void scan_remotePublicRepo() throws MalformedURLException {
        CxScanConfig config = initScaConfig();
        config.getScaConfig().setSourceLocationType(SourceLocationType.REMOTE_REPOSITORY);
        RemoteRepositoryInfo repoInfo = new RemoteRepositoryInfo();

        URL repoUrl = new URL(props.getProperty("sca.remotePublicRepoUrl"));
        repoInfo.setUrl(repoUrl);

        config.getScaConfig().setRemoteRepositoryInfo(repoInfo);

        DependencyScanResults scanResults = scanUsing(config);
        checkCommonAssertions(scanResults);

    }

    @Test
    @Ignore("Needs specific network configuration with a proxy.")
    public void runScaScanWithProxy() throws MalformedURLException, CxClientException {
        CxScanConfig config = initScaConfig();
        setProxy(config);
        DependencyScanResults scanResults = scanUsing(config);
        checkCommonAssertions(scanResults);
    }

    private Path extractTestProjectFromResources() {
        InputStream testProjectStream = getTestProjectStream();
        Path tempDirectory = createTempDirectory();
        extractResourceToDir(testProjectStream, tempDirectory);
        return tempDirectory;
    }

    private void extractResourceToDir(InputStream source, Path targetDir) {
        log.info("Unpacking sources into the temp dir.");
        int fileCount = 0;
        try (ArchiveInputStream inputStream = new ArchiveStreamFactory().createArchiveInputStream(source)) {
            ArchiveEntry entry;
            while ((entry = inputStream.getNextEntry()) != null) {
                if (!inputStream.canReadEntryData(entry)) {
                    throw new IOException(String.format("Unable to read entry: %s", entry));
                }
                Path fullTargetPath = targetDir.resolve(entry.getName());
                File targetFile = fullTargetPath.toFile();
                if (entry.isDirectory()) {
                    extractDirectory(targetFile);
                } else {
                    extractFile(inputStream, targetFile);
                    fileCount++;
                }
            }
        } catch (IOException | ArchiveException e) {
            failOnException(e);
        }
        log.info("Files extracted: {}", fileCount);
    }

    private static void extractFile(ArchiveInputStream inputStream, File targetFile) throws IOException {
        File parent = targetFile.getParentFile();
        extractDirectory(parent);
        try (OutputStream outputStream = Files.newOutputStream(targetFile.toPath())) {
            IOUtils.copy(inputStream, outputStream);
        }
    }

    private static void extractDirectory(File targetFile) throws IOException {
        if (!targetFile.isDirectory() && !targetFile.mkdirs()) {
            throw new IOException(String.format("Failed to create directory %s", targetFile));
        }
    }

    private static Path createTempDirectory() {
        String systemTempDir = FileUtils.getTempDirectoryPath();
        String subdir = String.format("common-client-tests-%s", UUID.randomUUID());
        Path result = Paths.get(systemTempDir, subdir);

        log.info("Creating a temp dir: {}", result);
        boolean success = result.toFile().mkdir();
        if (!success) {
            Assert.fail("Failed to create temp dir.");
        }
        return result;
    }

    private static void deleteDir(Path directory) {
        if (directory == null) {
            return;
        }

        log.info("Deleting '{}'", directory);
        try {
            FileUtils.deleteDirectory(directory.toFile());
        } catch (IOException e) {
            log.warn("Failed to delete temp dir.", e);
        }
    }

    private static InputStream getTestProjectStream() {
        String srcResourceName = ScaScanTests.PACKED_SOURCES_TO_SCAN;
        log.info("Getting resource stream from '{}'", srcResourceName);
        return Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(srcResourceName);
    }

    private DependencyScanResults scanUsing(CxScanConfig config) throws MalformedURLException, CxClientException {
        CxShragaClient client = new CxShragaClient(config, log);
        DependencyScanResults results = null;
        try {
            client.init();
            client.createDependencyScan();
            results = client.waitForDependencyScanResults();
        } catch (Exception e) {
            failOnException(e);
        }
        return results;
    }

    private void checkCommonAssertions(DependencyScanResults results) {
        Assert.assertNotNull("Scan results are null.", results);
        Assert.assertNull("OSA results are not null.", results.getOsaResults());

        SCAResults scaResults = results.getScaResults();
        Assert.assertNotNull("SCA results are null", scaResults);
        Assert.assertNotNull("SCA summary is null", scaResults.getSummary());
        Assert.assertTrue("Scan ID is empty", StringUtils.isNotEmpty(scaResults.getScanId()));
        Assert.assertTrue("Web report link is empty", StringUtils.isNotEmpty(scaResults.getWebReportLink()));
    }

    private static CxScanConfig initScaConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setDependencyScannerType(DependencyScannerType.SCA);
        config.setSastEnabled(false);
        config.setProjectName(props.getProperty("sca.projectName"));

        SCAConfig sca = TestingUtils.getScaConfig(props);
        config.setScaConfig(sca);

        return config;
    }
}
