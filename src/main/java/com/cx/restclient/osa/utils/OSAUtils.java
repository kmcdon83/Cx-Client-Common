package com.cx.restclient.osa.utils;

import com.cx.restclient.common.ShragaUtils;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.osa.dto.OSASummaryResults;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import java.io.File;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static com.cx.restclient.common.CxPARAM.CX_REPORT_LOCATION;

/**
 * Created by Galn on 07/02/2018.
 */
public abstract class OSAUtils {

    private static final String[] SUPPORTED_EXTENSIONS = {"jar", "war", "ear", "aar", "dll", "exe", "msi", "nupkg", "egg", "whl", "tar.gz", "gem", "deb", "udeb",
            "dmg", "drpm", "rpm", "pkg.tar.xz", "swf", "swc", "air", "apk", "zip", "gzip", "tar.bz2", "tgz", "c", "cc", "cp", "cpp", "css", "c++", "h", "hh", "hpp",
            "hxx", "h++", "m", "mm", "pch", "java", "c#", "cs", "csharp", "go", "goc", "js", "plx", "pm", "ph", "cgi", "fcgi", "psgi", "al", "perl", "t", "p6m", "p6l", "nqp,6pl", "6pm",
            "p6", "php", "py", "rb", "swift", "clj", "cljx", "cljs", "cljc"};

    private static final String INCLUDE_ALL_EXTENSIONS = "**/**";

    public static final String DEFAULT_ARCHIVE_INCLUDES = "**/.*jar,**/*.war,**/*.ear,**/*.sca,**/*.gem,**/*.whl,**/*.egg,**/*.tar,**/*.tar.gz,**/*.tgz,**/*.zip,**/*.rar";


    public static void writeToOsaListToFile(File dir, String osaDependenciesJson, Logger log) {
        try {
            File file = new File(dir, "OSADependencies.json");
            FileUtils.writeStringToFile(file, osaDependenciesJson, Charset.defaultCharset());
            log.info("OSA dependencies saved to file: [" + file.getAbsolutePath() + "]");
        } catch (Exception e) {
            log.info("Failed to write OSA dependencies to file: " + e.getMessage());
        }

    }

    public static String composeProjectOSASummaryLink(String url, long projectId) {
        return String.format(url + "/CxWebClient/SPA/#/viewer/project/%s", projectId);
    }

    public static Properties generateOSAScanConfiguration(String folderExclusions, String filterPatterns, String archiveIncludes, String scanFolder, boolean installBeforeScan, Logger log) {
        Properties ret = new Properties();
        filterPatterns = StringUtils.defaultString(filterPatterns);
        archiveIncludes = StringUtils.defaultString(archiveIncludes);

        Map<String, List<String>> stringListMap = ShragaUtils.generateIncludesExcludesPatternLists(folderExclusions, filterPatterns, log);

        List<String> inclusions = stringListMap.get(ShragaUtils.INCLUDES_LIST);
        List<String> exclusions = stringListMap.get(ShragaUtils.EXCLUDES_LIST);

        String includesString = StringUtils.join(inclusions, ",");
        String excludesString = StringUtils.join(exclusions, ",");

        if (StringUtils.isNotEmpty(includesString)) {
            ret.put("includes", includesString);
        } else {
            ret.put("includes", INCLUDE_ALL_EXTENSIONS);
        }

        if (StringUtils.isNotEmpty(excludesString)) {
            ret.put("excludes", excludesString);
        }

        ret.put("acceptExtensionsList", SUPPORTED_EXTENSIONS);

        if (StringUtils.isNotEmpty(archiveIncludes)) {
            String[] archivePatterns = archiveIncludes.split("\\s*,\\s*"); //split by comma and trim (spaces + newline)
            for (int i = 0; i < archivePatterns.length; i++) {
                if (StringUtils.isNotEmpty(archivePatterns[i]) && archivePatterns[i].startsWith("*.")) {
                    archivePatterns[i] = "**/" + archivePatterns[i];
                }
            }
            archiveIncludes = StringUtils.join(archivePatterns, ",");
            ret.put("archiveIncludes", archiveIncludes);
        } else {
            ret.put("archiveIncludes", DEFAULT_ARCHIVE_INCLUDES);
        }

        ret.put("archiveExtractionDepth", "4");

        if (installBeforeScan) {
            ret.put("npm.runPreStep", "true");
            ret.put("bower.runPreStep", "false");
            ret.put("npm.ignoreScripts", "true");
            setResolveDependencies(ret,"true");
        }else {
            setResolveDependencies(ret,"false");
        }

        ret.put("d", scanFolder);

        return ret;
    }

    private static void setResolveDependencies(Properties ret, String resolveDependencies) {
        ret.put("nuget.resolveDependencies", resolveDependencies);
        ret.put("nuget.restoreDependencies", resolveDependencies);
        ret.put("python.resolveDependencies", resolveDependencies);
        ret.put("python.ignorePipInstallErrors", resolveDependencies);
    }

    public static void printOSAResultsToConsole(OSAResults osaResults, boolean enableViolations, Logger log) {
        OSASummaryResults osaSummaryResults = osaResults.getResults();
        log.info("----------------------------Checkmarx Scan Results(CxOSA):-------------------------------");
        log.info("");
        log.info("------------------------");
        log.info("Vulnerabilities Summary:");
        log.info("------------------------");
        log.info("OSA high severity results: " + osaSummaryResults.getTotalHighVulnerabilities());
        log.info("OSA medium severity results: " + osaSummaryResults.getTotalMediumVulnerabilities());
        log.info("OSA low severity results: " + osaSummaryResults.getTotalLowVulnerabilities());
        log.info("Vulnerability score: " + osaSummaryResults.getVulnerabilityScore());
        log.info("");
        log.info("-----------------------");
        log.info("Libraries Scan Results:");
        log.info("-----------------------");
        log.info("Open-source libraries: " + osaSummaryResults.getTotalLibraries());
        log.info("Vulnerable and outdated: " + osaSummaryResults.getVulnerableAndOutdated());
        log.info("Vulnerable and updated: " + osaSummaryResults.getVulnerableAndUpdated());
        log.info("Non-vulnerable libraries: " + osaSummaryResults.getNonVulnerableLibraries());
        log.info("");
        log.info("OSA scan results location: " + osaResults.getOsaProjectSummaryLink());
        log.info("-----------------------------------------------------------------------------------------");
    }

    public static void writeJsonToFile(String name, Object jsonObj, File workDirectory, Logger log) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String now = new SimpleDateFormat("dd_MM_yyyy-HH_mm_ss").format(new Date());
            String fileName = name + "_" + now + ".json";
            File jsonFile = new File(workDirectory + CX_REPORT_LOCATION, fileName);
            String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObj);
            FileUtils.writeStringToFile(jsonFile, json);
            log.info(name + " json location: " + workDirectory + CX_REPORT_LOCATION + File.separator + fileName);
        } catch (Exception ex) {
            log.warn("Failed to write OSA JSON report (" + name + ") to file: " + ex.getMessage());
        }
    }
}
