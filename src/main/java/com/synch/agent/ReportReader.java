package com.synch.agent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class ReportReader {

    static JsonNode loadVulnerabilities() throws Exception {
        String text = Files.readString(Path.of("trivy-report.json"));   // 1. full path ("path.of()") ila makansh lfile li baghi tparsi f same folder dial prog

        ObjectMapper mapper = new ObjectMapper();
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
}
