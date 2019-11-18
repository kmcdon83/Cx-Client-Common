package com.cx.restclient.common;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.osa.dto.OSASummaryResults;
import com.cx.restclient.sast.dto.SASTResults;
import com.cx.restclient.sca.dto.SCAResults;
import com.cx.restclient.sca.dto.SCASummaryResults;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.cx.restclient.common.CxPARAM.PROJECT_POLICY_VIOLATED_STATUS;

/**
 * Created by: dorg.
 * Date: 4/12/2018.
 */
public abstract class ShragaUtils {
    //Util methods
    public static String getBuildFailureResult(CxScanConfig config, SASTResults sastResults, DependencyScanResults dependencyScanResults) {
        StringBuilder res = new StringBuilder();
        isThresholdExceeded(config, sastResults, dependencyScanResults, res);
        isThresholdForNewResultExceeded(config, sastResults, res);
        isPolicyViolated(config, sastResults, dependencyScanResults, res);

        return res.toString();
    }

    private static boolean isPolicyViolated(CxScanConfig config, SASTResults sastResults, DependencyScanResults dependencyScanResults, StringBuilder res) {
        boolean isPolicyViolated = config.getEnablePolicyViolations() &&
                ((dependencyScanResults != null &&
                        dependencyScanResults.getOsaResults() != null &&
                        dependencyScanResults.getOsaResults().getOsaPolicies() != null &&
                        dependencyScanResults.getOsaResults().getOsaPolicies().size() > 0) ||
                        (sastResults != null && sastResults.getSastPolicies().size() > 0));

        if (isPolicyViolated) {
            res.append(PROJECT_POLICY_VIOLATED_STATUS).append("\n");
        }
        return isPolicyViolated;
    }

    public static boolean isThresholdExceeded(CxScanConfig config, SASTResults sastResults, DependencyScanResults dependencyScanResults, StringBuilder res) {
        boolean thresholdExceeded = false;
        if (config.isSASTThresholdEffectivelyEnabled() && sastResults != null && sastResults.isSastResultsReady()) {
            final String SEVERITY_TYPE = "CxSAST";
            thresholdExceeded = isSeverityExceeded(sastResults.getHigh(), config.getSastHighThreshold(), res, "high", SEVERITY_TYPE);
            thresholdExceeded |= isSeverityExceeded(sastResults.getMedium(), config.getSastMediumThreshold(), res, "medium", SEVERITY_TYPE);
            thresholdExceeded |= isSeverityExceeded(sastResults.getLow(), config.getSastLowThreshold(), res, "low", SEVERITY_TYPE);
        }

        if (config.isOSAThresholdEffectivelyEnabled() && dependencyScanResults != null) {
            SCAResults scaResults = dependencyScanResults.getScaResults();
            OSAResults osaResults = dependencyScanResults.getOsaResults();
            int totalHigh = 0, totalMedium = 0, totalLow = 0;
            String severityType = null;

            if (scaResults != null) {
                SCASummaryResults summary = scaResults.getSummary();
                if (summary != null) {
                    severityType = "SCA";
                    totalHigh = summary.getHighVulnerabilitiesCount();
                    totalMedium = summary.getMediumVulnerabilitiesCount();
                    totalLow = summary.getLowVulnerabilitiesCount();
                }
            } else if (osaResults != null && osaResults.isOsaResultsReady()) {
                OSASummaryResults summary = osaResults.getResults();
                if (summary != null) {
                    severityType = "CxOSA";
                    totalHigh = summary.getTotalHighVulnerabilities();
                    totalMedium = summary.getTotalMediumVulnerabilities();
                    totalLow = summary.getTotalLowVulnerabilities();
                }
            }

            if (severityType != null) {
                thresholdExceeded |= isSeverityExceeded(totalHigh, config.getOsaHighThreshold(), res, "high", severityType);
                thresholdExceeded |= isSeverityExceeded(totalMedium, config.getOsaMediumThreshold(), res, "medium", severityType);
                thresholdExceeded |= isSeverityExceeded(totalLow, config.getOsaLowThreshold(), res, "low", severityType);
            }
        }
        return thresholdExceeded;
    }

    public static boolean isThresholdForNewResultExceeded(CxScanConfig config, SASTResults sastResults, StringBuilder res) {
        boolean exceeded = false;

        if (sastResults != null && sastResults.isSastResultsReady() && config.getSastNewResultsThresholdEnabled()) {
            String severity = config.getSastNewResultsThresholdSeverity();

            if ("LOW".equals(severity)) {
                if (sastResults.getNewLow() > 0) {
                    res.append("One or more new results of low severity\n");
                    exceeded = true;
                }
                severity = "MEDIUM";
            }

            if ("MEDIUM".equals(severity)) {
                if (sastResults.getNewMedium() > 0) {
                    res.append("One or more new results of medium severity\n");
                    exceeded = true;
                }
                severity = "HIGH";
            }

            if ("HIGH".equals(severity)) {
                if (sastResults.getNewHigh() > 0) {
                    res.append("One or more New results of high severity\n");
                    exceeded = true;
                }
            }
        }

        return exceeded;
    }

    private static boolean isSeverityExceeded(int result, Integer threshold, StringBuilder res, String severity, String severityType) {
        boolean fail = false;
        if (threshold != null && result > threshold) {
            res.append(String.format("%s %s severity results are above threshold. Results: %d. Threshold: %d.\n",
                    severityType, severity, result, threshold));
            fail = true;
        }
        return fail;
    }

    public static Map<String, List<String>> generateIncludesExcludesPatternLists(String folderExclusions, String filterPattern, Logger log) {

        String excludeFoldersPattern = processExcludeFolders(folderExclusions, log);
        String combinedPatterns = "";

        if (StringUtils.isEmpty(filterPattern) && StringUtils.isEmpty(excludeFoldersPattern)) {
            combinedPatterns = "";
        } else if (!StringUtils.isEmpty(filterPattern) && StringUtils.isEmpty(excludeFoldersPattern)) {
            combinedPatterns = filterPattern;
        } else if (StringUtils.isEmpty(filterPattern) && !StringUtils.isEmpty(excludeFoldersPattern)) {
            combinedPatterns = excludeFoldersPattern;
        } else {
            combinedPatterns = filterPattern + "," + excludeFoldersPattern;
        }

        return convertPatternsToLists(combinedPatterns);
    }

    public static String processExcludeFolders(String folderExclusions, Logger log) {
        if (StringUtils.isEmpty(folderExclusions)) {
            return "";
        }

        StringBuilder result = new StringBuilder();
        String[] patterns = StringUtils.split(folderExclusions, ",\n");
        for (String p : patterns) {
            p = p.trim();
            if (p.length() > 0) {
                result.append("!**/");
                result.append(p);
                result.append("/**,");
            }
        }

        log.info("Exclude folders converted to: '" + result.toString() + "'");
        return result.toString();
    }

    public static final String INCLUDES_LIST = "includes";
    public static final String EXCLUDES_LIST = "excludes";

    public static Map<String, List<String>> convertPatternsToLists(String filterPatterns) {
        filterPatterns = StringUtils.defaultString(filterPatterns);
        List<String> inclusions = new ArrayList<String>();
        List<String> exclusions = new ArrayList<String>();
        String[] filters = filterPatterns.replace("\n", "").replace("\r", "").split("\\s*,\\s*"); //split by comma and trim (spaces + newline)
        for (String filter : filters) {
            if (StringUtils.isNotEmpty(filter)) {
                if (!filter.startsWith("!")) {
                    inclusions.add(filter.trim());
                } else if (filter.length() > 1) {
                    filter = filter.substring(1); // Trim the "!"
                    exclusions.add(filter.trim());
                }
            }
        }

        Map<String, List<String>> ret = new HashMap<String, List<String>>();
        ret.put(INCLUDES_LIST, inclusions);
        ret.put(EXCLUDES_LIST, exclusions);

        return ret;
    }

    public static String formatDate(String date, String fromFormat, String toFormat) {
        SimpleDateFormat fromDate = new SimpleDateFormat(fromFormat);
        SimpleDateFormat toDate = new SimpleDateFormat(toFormat);
        String ret = "";
        try {
            ret = toDate.format(fromDate.parse(date));
        } catch (Exception ignored) {

        }
        return ret;
    }

    public static String getTimestampSince(long startTimeSec) {
        long elapsedSec = System.currentTimeMillis() / 1000 - startTimeSec;
        long hours = elapsedSec / 3600;
        long minutes = elapsedSec % 3600 / 60;
        long seconds = elapsedSec % 60;
        String hoursStr = (hours < 10) ? ("0" + hours) : (Long.toString(hours));
        String minutesStr = (minutes < 10) ? ("0" + minutes) : (Long.toString(minutes));
        String secondsStr = (seconds < 10) ? ("0" + seconds) : (Long.toString(seconds));
        return String.format("%s:%s:%s", hoursStr, minutesStr, secondsStr);
    }
}
