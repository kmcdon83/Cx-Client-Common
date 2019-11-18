package com.cx.restclient.common;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.sast.dto.SASTResults;
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
    public static String getBuildFailureResult(CxScanConfig config, SASTResults sastResults, OSAResults osaResults) {
        StringBuilder res = new StringBuilder("");
        isThresholdExceeded(config, sastResults, osaResults, res);
        isThresholdForNewResultExceeded(config, sastResults, res);
        isPolicyViolated(config, sastResults, osaResults, res);

        return res.toString();
    }

    public static boolean isPolicyViolated(CxScanConfig config, SASTResults sastResults, OSAResults osaResults, StringBuilder res) {
        boolean isPolicyViolated = config.getEnablePolicyViolations() && ((osaResults!=null && osaResults.getOsaPolicies().size() > 0) || (sastResults != null && sastResults.getSastPolicies().size() > 0));
        if(isPolicyViolated) {
            res.append(PROJECT_POLICY_VIOLATED_STATUS).append("\n");
        }
        return isPolicyViolated;
    }

    public static boolean isThresholdExceeded(CxScanConfig config, SASTResults sastResults, OSAResults osaResults, StringBuilder res) {
        boolean thresholdExceeded = false;
        if (config.isSASTThresholdEffectivelyEnabled() && sastResults != null && sastResults.isSastResultsReady()) {
            thresholdExceeded = isSeverityExceeded(sastResults.getHigh(), config.getSastHighThreshold(), res, "high", "CxSAST ");
            thresholdExceeded |= isSeverityExceeded(sastResults.getMedium(), config.getSastMediumThreshold(), res, "medium", "CxSAST ");
            thresholdExceeded |= isSeverityExceeded(sastResults.getLow(), config.getSastLowThreshold(), res, "low", "CxSAST ");
        }
        if (config.isOSAThresholdEffectivelyEnabled() && osaResults != null && osaResults.isOsaResultsReady()) {
            thresholdExceeded |= isSeverityExceeded(osaResults.getResults().getTotalHighVulnerabilities(), config.getOsaHighThreshold(), res, "high", "CxOSA  ");
            thresholdExceeded |= isSeverityExceeded(osaResults.getResults().getTotalMediumVulnerabilities(), config.getOsaMediumThreshold(), res, "medium", "CxOSA  ");
            thresholdExceeded |= isSeverityExceeded(osaResults.getResults().getTotalLowVulnerabilities(), config.getOsaLowThreshold(), res, "low", "CxOSA  ");
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
            res.append(severityType).append(severity).append(" severity results are above threshold. Results: ").append(result).append(". Threshold: ").append(threshold).append(". \n");
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
}
