package com.cx.restclient.sast.utils.zip;


import com.cx.restclient.common.ShragaUtils;
import com.cx.restclient.configuration.CxScanConfig;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.cx.restclient.sast.utils.SASTParam.TEMP_FILE_NAME_TO_ZIP;


/**
 * CxZipUtils generates the patterns used for zipping the workspace folder
 */


public abstract class CxZipUtils {

    public static File zipWorkspaceFolder(CxScanConfig config, long maxZipBytes, Logger log) throws IOException {
        Map<String, List<String>> stringListMap = ShragaUtils.generateIncludesExcludesPatternLists(config.getSastFolderExclusions(), config.getSastFilterPattern(), log);
        List<String> includes = stringListMap.get(ShragaUtils.INCLUDES_LIST);
        List<String> excludes = stringListMap.get(ShragaUtils.EXCLUDES_LIST);

        CxZip cxZip = new CxZip(TEMP_FILE_NAME_TO_ZIP, maxZipBytes, log);

        return cxZip.zipWorkspaceFolder(new File(config.getSourceDir()), includes.toArray(new String[includes.size()]), excludes.toArray(new String[excludes.size()]));

    }
}

