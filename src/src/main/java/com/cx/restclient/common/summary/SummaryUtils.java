package com.cx.restclient.common.summary;

import com.cx.restclient.common.ShragaUtils;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.osa.dto.OSASummaryResults;
import com.cx.restclient.sast.dto.SASTResults;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public abstract class SummaryUtils {

    public static String generateSummary(SASTResults sastResults, OSAResults osaResults, CxScanConfig config) throws IOException, TemplateException {

        Configuration cfg = new Configuration(new Version("2.3.23"));
        cfg.setClassForTemplateLoading(SummaryUtils.class, "/com/cx/report");
        Template template = cfg.getTemplate("report.ftl");

        Map<String, Object> templateData = new HashMap<String, Object>();
        templateData.put("config", config);
        templateData.put("sast", sastResults);
        templateData.put("osa", osaResults);

        //calculated params:

        boolean buildFailed = false;
        boolean policyViolated = false;
        //sast:
        if (config.getSastEnabled() && sastResults.isSastResultsReady()) {
            boolean sastThresholdExceeded = ShragaUtils.isThresholdExceeded(config, sastResults, null, new StringBuilder());
            boolean sastNewResultsExceeded = ShragaUtils.isThresholdForNewResultExceeded(config, sastResults, new StringBuilder());
            templateData.put("sastThresholdExceeded", sastThresholdExceeded);
            templateData.put("sastNewResultsExceeded", sastNewResultsExceeded);
            buildFailed = sastThresholdExceeded || sastNewResultsExceeded;
            //calculate sast bars:
            float maxCount = Math.max(sastResults.getHigh(), Math.max(sastResults.getMedium(), sastResults.getLow()));
            float sastBarNorm = maxCount * 10f / 9f;

            //sast high bars
            float sastHighTotalHeight = (float) sastResults.getHigh() / sastBarNorm * 238f;
            float sastHighNewHeight = calculateNewBarHeight(sastResults.getNewHigh(), sastResults.getHigh(), sastHighTotalHeight);
            float sastHighRecurrentHeight = sastHighTotalHeight - sastHighNewHeight;
            templateData.put("sastHighTotalHeight", sastHighTotalHeight);
            templateData.put("sastHighNewHeight", sastHighNewHeight);
            templateData.put("sastHighRecurrentHeight", sastHighRecurrentHeight);
            /*if (config.getEnablePolicyViolations() && !sastResults.getSastViolations().isEmpty()){
                policyViolated = true;
            }*/

            //sast medium bars
            float sastMediumTotalHeight = (float) sastResults.getMedium() / sastBarNorm * 238f;
            float sastMediumNewHeight = calculateNewBarHeight(sastResults.getNewMedium(), sastResults.getMedium(), sastMediumTotalHeight);
            float sastMediumRecurrentHeight = sastMediumTotalHeight - sastMediumNewHeight;
            templateData.put("sastMediumTotalHeight", sastMediumTotalHeight);
            templateData.put("sastMediumNewHeight", sastMediumNewHeight);
            templateData.put("sastMediumRecurrentHeight", sastMediumRecurrentHeight);

            //sast low bars
            float sastLowTotalHeight = (float) sastResults.getLow() / sastBarNorm * 238f;
            float sastLowNewHeight = calculateNewBarHeight(sastResults.getNewLow(), sastResults.getLow(), sastLowTotalHeight);
            float sastLowRecurrentHeight = sastLowTotalHeight - sastLowNewHeight;
            templateData.put("sastLowTotalHeight", sastLowTotalHeight);
            templateData.put("sastLowNewHeight", sastLowNewHeight);
            templateData.put("sastLowRecurrentHeight", sastLowRecurrentHeight);
        }

        //osa:
        if (config.getOsaEnabled() && osaResults.isOsaResultsReady()) {
            boolean osaThresholdExceeded = ShragaUtils.isThresholdExceeded(config, null, osaResults, new StringBuilder());
            templateData.put("osaThresholdExceeded", osaThresholdExceeded);
            buildFailed |= osaThresholdExceeded;
            if (config.getEnablePolicyViolations() && !osaResults.getOsaViolations().isEmpty()){
                policyViolated = true;
            }
            //calculate osa bars:
            OSASummaryResults osaSummaryResults = osaResults.getResults();
            int osaHigh = osaSummaryResults.getTotalHighVulnerabilities();
            int osaMedium = osaSummaryResults.getTotalMediumVulnerabilities();
            int osaLow = osaSummaryResults.getTotalLowVulnerabilities();
            float osaMaxCount = Math.max(osaHigh, Math.max(osaMedium, osaLow));
            float osaBarNorm = osaMaxCount * 10f / 9f;

            float osaHighTotalHeight = (float) osaHigh / osaBarNorm * 238f;
            float osaMediumTotalHeight = (float) osaMedium / osaBarNorm * 238f;
            float osaLowTotalHeight = (float) osaLow / osaBarNorm * 238f;

            templateData.put("osaHighTotalHeight", osaHighTotalHeight);
            templateData.put("osaMediumTotalHeight", osaMediumTotalHeight);
            templateData.put("osaLowTotalHeight", osaLowTotalHeight);
        }

        String policyLabel = osaResults.getOsaPolicies().size() == 1? "Policy": "Policies";
        templateData.put("policyLabel", policyLabel);

        templateData.put("policyViolated", policyViolated);
        buildFailed |= policyViolated;
        templateData.put("buildFailed", buildFailed);

        //generate the report:
        StringWriter writer = new StringWriter();
        template.process(templateData, writer);
        return writer.toString();
    }

    private static float calculateNewBarHeight(int newCount, int count, float totalHeight) {
        int minimalVisibilityHeight = 5;
        //new high
        float highNewHeightPx = (float) newCount / (float) count * totalHeight;
        //if new height is between 1 and 9 - give it a minimum height and if theres enough spce in total height
        if (isNewNeedChange(totalHeight, highNewHeightPx, minimalVisibilityHeight)) {
            highNewHeightPx = minimalVisibilityHeight;
        }

        return highNewHeightPx;
    }

    private static boolean isNewNeedChange(float highTotalHeightPx, float highNewHeightPx, int minimalVisibilityHeight) {
        return highNewHeightPx > 0 && highNewHeightPx < minimalVisibilityHeight && highTotalHeightPx > minimalVisibilityHeight * 2;
    }
}