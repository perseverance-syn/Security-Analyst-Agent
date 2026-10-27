package com.synch.agent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

record CveDetail(String packageName, String installedVersion, String fixedVersion,
        String severity, String title) {}

public class ReportReader {

    static ObjectMapper mapper = new ObjectMapper();

    static JsonNode loadVulnerabilities() throws Exception {
        String text = Files.readString(Path.of("trivy-report.json"));   // 1. full path ("path.of()") ila makansh lfile li baghi tparsi f same folder dial prog

        
        JsonNode root = mapper.readTree(text);                    // 2. same as before

        JsonNode target = root.get("Results").get(0).get("Vulnerabilities");
        // 3.same indentation  =  neighbors 

        return target;
    }                                            // ← method 1 closes

    public static String buildReport() throws Exception {

        StringBuilder built = new StringBuilder();

        for (JsonNode vuln : loadVulnerabilities()) {
            String severity = vuln.get("Severity").asString();
            if (severity.equals("CRITICAL")) {
                String vulnid = vuln.get("VulnerabilityID").asString();
                String pkgname = vuln.get("PkgName").asString();
                String installedversion = vuln.get("InstalledVersion").asString();

                if (!vuln.has("FixedVersion")) {
                    built.append(vulnid + "|" + pkgname + "|" + installedversion + "-> there's no fix yet" + "\n");

                } else {
                    String fixedversion = vuln.get("FixedVersion").asString();
                    built.append(vulnid + "|" + pkgname + "|" + installedversion + "->" + fixedversion + "\n");
                }

            }
        }
        String result = built.toString();
        return result;

    }

    static Set<String> criticalPairs() throws Exception {
        Set<String> s = new HashSet<String>();
        for (JsonNode vuln : loadVulnerabilities()) {
            String severity = vuln.get("Severity").asString();
            if (severity.equals("CRITICAL")) {
                String vulnid = vuln.get("VulnerabilityID").asString();
                String pkgname = vuln.get("PkgName").asString();
                s.add(pkgname + "|" + vulnid);
            }

        }
        return s;
    }

    static Set<String> noFixPairs() throws Exception {
        Set<String> nofixpair = new HashSet<String>();
        for (JsonNode vuln : loadVulnerabilities()) {
            String severity = vuln.get("Severity").asString();
            if (severity.equals("CRITICAL") && !vuln.has("FixedVersion")) {
                String vulnid = vuln.get("VulnerabilityID").asString();
                String pkgname = vuln.get("PkgName").asString();

                nofixpair.add(pkgname + "|" + vulnid);

            }
        }
        return nofixpair;

    }

    static String cveDetails(String cveid) throws Exception {
        List<CveDetail> matches = new ArrayList<>();

        for (JsonNode vuln : loadVulnerabilities()) {
            String vulnid = vuln.get("VulnerabilityID").asString();
            if (vulnid.equals(cveid)) {
                String packageName = vuln.get("PkgName").asString();
                String installedVersion = vuln.get("InstalledVersion").asString();
                String fixedVersion = null;
                if(vuln.has("FixedVersion")){
                    fixedVersion = vuln.get("FixedVersion").asString() ; 
                }
                String severity = vuln.get("Severity").asString();
                String title = null;
                if(vuln.has("Title")){
                    title = vuln.get("Title").asString();  
                }

                matches.add(new CveDetail(packageName, installedVersion, fixedVersion, severity, title));

            }

        }
        if (matches.isEmpty()) {
            return "{\"error\": \"CVE not found in this report\"}";
        }

        String cvedetails = mapper.writeValueAsString(matches);
        return cvedetails;
    }

}
