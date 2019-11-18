package com.cx.restclient.sast.utils;

import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sast.dto.CxXMLResults;
import com.cx.restclient.sast.dto.SASTResults;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import static com.cx.restclient.common.CxPARAM.CX_REPORT_LOCATION;
import static com.cx.restclient.sast.utils.SASTParam.PDF_REPORT_NAME;

/**
 * Created by Galn on 07/02/2018.
 */
public abstract class SASTUtils {

    public static void deleteTempZipFile(File zipTempFile, Logger log) {
        if (zipTempFile.exists() && !zipTempFile.delete()) {
            log.warn("Failed to delete temporary zip file: " + zipTempFile.getAbsolutePath());
        } else {
            log.info("Temporary file deleted");
        }
    }

    public static CxXMLResults convertToXMLResult(byte[] cxReport) throws CxClientException {
        CxXMLResults reportObj = null;
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(cxReport);
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(CxXMLResults.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();

            reportObj = (CxXMLResults) unmarshaller.unmarshal(byteArrayInputStream);

        } catch (JAXBException e) {
            throw new CxClientException("Failed to parse xml report: " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(byteArrayInputStream);
        }
        return reportObj;
    }

    public static void printSASTResultsToConsole(SASTResults sastResults,boolean enableViolations, Logger log) {

        String highNew = sastResults.getNewHigh() > 0 ? " (" + sastResults.getNewHigh() + " new)" : "";
        String mediumNew = sastResults.getNewMedium() > 0 ? " (" + sastResults.getNewMedium() + " new)" : "";
        String lowNew = sastResults.getNewLow() > 0 ? " (" + sastResults.getNewLow() + " new)" : "";
        String infoNew = sastResults.getNewInfo() > 0 ? " (" + sastResults.getNewInfo() + " new)" : "";

        log.info("----------------------------Checkmarx Scan Results(CxSAST):-------------------------------");
        log.info("High severity results: " + sastResults.getHigh() + highNew);
        log.info("Medium severity results: " + sastResults.getMedium() + mediumNew);
        log.info("Low severity results: " + sastResults.getLow() + lowNew);
        log.info("Information severity results: " + sastResults.getInformation() + infoNew);
        log.info("");
        log.info("Scan results location: " + sastResults.getSastScanLink());
        log.info("------------------------------------------------------------------------------------------\n");
    }

    //PDF Report
    public static String writePDFReport(byte[] scanReport, File workspace, String pdfFileName,  Logger log) {
        try {
            FileUtils.writeByteArrayToFile(new File(workspace + CX_REPORT_LOCATION, pdfFileName), scanReport);
            log.info("PDF report location: " + workspace + CX_REPORT_LOCATION + File.separator + pdfFileName);
        } catch (Exception e) {
            log.error("Failed to write PDF report to workspace: ", e.getMessage());
            pdfFileName ="";
        }
        return pdfFileName;
    }
}
