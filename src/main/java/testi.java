import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.SCAConfig;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.sast.dto.SASTResults;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;


/**
 * Created by Galn on 04/03/2018.
 */
public class testi {
    private static String DEFAULT_FILTER_PATTERNS = "!**/_cvs/**/*, !**/.svn/**/*,   !**/.hg/**/*,   !**/.git/**/*,  !**/.bzr/**/*, !**/bin/**/*," +
            "!**/obj/**/*,  !**/backup/**/*, !**/.idea/**/*, !**/*.DS_Store, !**/*.ipr,     !**/*.iws,   " +
            "!**/*.bak,     !**/*.tmp,       !**/*.aac,      !**/*.aif,      !**/*.iff,     !**/*.m3u,   !**/*.mid,   !**/*.mp3,  " +
            "!**/*.mpa,     !**/*.ra,        !**/*.wav,      !**/*.wma,      !**/*.3g2,     !**/*.3gp,   !**/*.asf,   !**/*.asx,  " +
            "!**/*.avi,     !**/*.flv,       !**/*.mov,      !**/*.mp4,      !**/*.mpg,     !**/*.rm,    !**/*.swf,   !**/*.vob,  " +
            "!**/*.wmv,     !**/*.bmp,       !**/*.gif,      !**/*.jpg,      !**/*.png,     !**/*.psd,   !**/*.tif,   !**/*.swf,  " +
            "!**/*.jar,     !**/*.zip,       !**/*.rar,      !**/*.exe,      !**/*.dll,     !**/*.pdb,   !**/*.7z,    !**/*.gz,   " +
            "!**/*.tar.gz,  !**/*.tar,       !**/*.gz,       !**/*.ahtm,     !**/*.ahtml,   !**/*.fhtml, !**/*.hdm,   " +
            "!**/*.hdml,    !**/*.hsql,      !**/*.ht,       !**/*.hta,      !**/*.htc,     !**/*.htd,   !**/*.war,   !**/*.ear,  " +
            "!**/*.htmls,   !**/*.ihtml,     !**/*.mht,      !**/*.mhtm,     !**/*.mhtml,   !**/*.ssi,   !**/*.stm,   " +
            "!**/*.stml,    !**/*.ttml,      !**/*.txn,      !**/*.xhtm,     !**/*.xhtml,   !**/*.class, !**/*.iml,   !Checkmarx/Reports/*.*, !**/node_modules/**/*";

    private static String DEFAULT_OSA_ARCHIVE_INCLUDE_PATTERNS = "*.zip, *.tgz, *.war, *.ear";


    public static void main(String[] args) throws Exception {
        SASTResults sastResults = null;
        // SASTResults lastSastResults = null;
        OSAResults osaResults = null;
        //  OSAResults lastOsaResults = null;
        Logger logi = LoggerFactory.getLogger("testush");


        CxScanConfig config = setConfigi();


        CxShragaClient shraga = new CxShragaClient(config, logi);
       // shraga.getClientVersion();
        shraga.init();

        try {
            if (config.getOsaEnabled()) {
                shraga.createOSAScan();
            } else if (config.getScaEnabled()) {
                shraga.createSCAScan();
            }
        } catch (Exception ex) {
            logi.error(ex.getMessage());
        }

        try {
            if (config.getSastEnabled()) {
                shraga.createSASTScan();
            }
        } catch (Exception ex) {
            logi.error(ex.getMessage());
        }

        try {
            if (config.getSastEnabled()) {
                sastResults = shraga.waitForSASTResults();
            }
        } catch (Exception ex) {
            logi.error(ex.getMessage());
        }

        try {
            if (config.getOsaEnabled()) {
                osaResults = shraga.waitForOSAResults();
            }
        } catch (Exception ex) {
            logi.error(ex.getMessage());
        }

        //lastSastResults = shraga.getLatestSASTResults();
     //   lastOsaResults = shraga.getLatestOSAResults();
       if (config.getEnablePolicyViolations()) {
            shraga.printIsProjectViolated();
        }
        //String buildFailedResult = ShragaUtils.getBuildFailureResult(config, sastResults, osaResults);
        String s = shraga.generateHTMLSummary();
        File file = new File("c:\\cxdev\\reports\\report.html");
        FileUtils.writeStringToFile(file, s);

        shraga.close();
    }


    private static CxScanConfig setConfigi() {
        CxScanConfig config = new CxScanConfig();

        configureSca(config);

        config.setSastEnabled(true);

        config.setSourceDir("c:\\cxdev\\projectsToScan\\BookStore_Small_CLI\\");
        config.setReportsDir(new File("c:\\cxdev\\reports\\"));

        config.setUrl("http://10.32.1.57");
        config.setUsername("myusername");
        config.setPassword("mypassword");

        config.setAvoidDuplicateProjectScans(false);

        config.setCxOrigin("common");
        config.setProjectName("CommonClientTest1");
        config.setPresetName("Default");

        config.setTeamPath("\\CxServer");

        config.setSastFolderExclusions("");
        config.setSastFilterPattern(DEFAULT_FILTER_PATTERNS);
        config.setSastScanTimeoutInMinutes(null);
        config.setScanComment("");
        config.setIncremental(false);
        config.setSynchronous(true);
        config.setSastThresholdsEnabled(false);
        config.setSastHighThreshold(1);
        config.setSastMediumThreshold(1);
        config.setSastLowThreshold(1);
        config.setGeneratePDFReport(true);
        config.setOsaEnabled(false);


        config.setOsaFilterPattern("");//TODO check
        config.setOsaArchiveIncludePatterns(DEFAULT_OSA_ARCHIVE_INCLUDE_PATTERNS);
        config.setOsaRunInstall(true);
        config.setOsaThresholdsEnabled(true);
        config.setOsaHighThreshold(10);
        config.setOsaMediumThreshold(0);
        config.setOsaLowThreshold(0);
        config.setDenyProject(false);
        config.setPublic(true);
        //config.setUseSSOLogin(false);
        //config.setZipFile();
        //config.setOsaDependenciesJson();
        config.setEnablePolicyViolations(true);

        return config;
    }

    private static void configureSca(CxScanConfig parentConfig) {
        parentConfig.setScaEnabled(false);

        SCAConfig config = new SCAConfig();
        config.setApiUrl("http://scaapp.lumodev.com");
        config.setAccessControlUrl("http://upgrade.dev-ac-checkmarx.com");
        config.setUsername("myusername");
        config.setPassword("mypassword");
        config.setTenant("Checkmarx");
        parentConfig.setScaConfig(config);
    }
}
