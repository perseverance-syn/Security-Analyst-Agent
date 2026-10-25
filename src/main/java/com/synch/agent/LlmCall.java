package com.synch.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

record JsonSchema(String name, JsonNode schema) {}

record ResponseFormat(String type, JsonSchema json_schema) {}

record ChatMessage(String role, String content) {}

record ChatRequest(String model, List<ChatMessage> messages, ResponseFormat response_format, double temperature) {}

record PackageFix(String packageName, String installedVersion, String fixedVersion,
        List<String> cves, int priority, String reason) {}

record TriageReport(List<PackageFix> fixes) {}

public class LlmCall {

    public static void main(String[] args) throws Exception {
        Set<String> reportPairs = ReportReader.criticalPairs();
        System.out.println("Report pairs: " + reportPairs.size());

        Set<String> noFix = ReportReader.noFixPairs();
        System.out.println("No-fix pairs: " + noFix.size());

        String apiKey = System.getenv("GROQ_API_KEY");   // reads the env variable

        String schemaText = """
                            {
                            "type": "object",
                            "properties": {
                                "fixes": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                    "packageName":      {"type": "string"},
                                    "installedVersion": {"type": "string"},
                                    "fixedVersion":     {"type": ["string", "null"]},
                                    "cves":             {"type": "array", "items": {"type": "string"}},
                                    "priority":         {"type": "integer"},
                                    "reason":           {"type": "string"}
                                    },
                                    "required": ["packageName", "installedVersion", "fixedVersion", "cves", "priority", "reason"]
                                }
                                }
                            },
                            "required": ["fixes"]
                            }
                            """;
        ObjectMapper mapper = new ObjectMapper();
        JsonNode shape = mapper.readTree(schemaText);

        ResponseFormat resformat = new ResponseFormat("json_schema", new JsonSchema("triage", shape));

        String builtReport = ReportReader.buildReport();

        String prompt = "You are a security analyst. Analyze these CRITICAL vulnerabilities from a container scan.\r\n"
                + //
                "Group them by package. Reply ONLY with JSON in exactly this shape:\r\n"
                + //
                "{\"fixes\": [{\"packageName\": \"...\", \"installedVersion\": \"...\", \"fixedVersion\": \"... or null if no fix\",\r\n"
                + //
                "\"cves\": [\"CVE-...\"], \"priority\": 1, \"reason\": \"one short sentence\"}]}\r\n"
                + //
                "Priority 1 = fix first. Packages with an available fix come before packages with no fix.\r\n"
                + //
                "Use ONLY CVE IDs from the list below. Do not invent any. If a package has some CVEs with a fix and some without, split it into two entries:\r\n"
                + //
                "one with the fixedVersion and only the fixable CVEs,\r\n"
                + //
                "and one with fixedVersion null and only the CVEs that have no fix." + " " + builtReport + "\n/no_think";

        HttpClient client = HttpClient.newHttpClient();
        List<ChatMessage> messages = new ArrayList<>();

        ChatMessage misage = new ChatMessage("user", prompt);
        messages.add(misage);

        for (int attempt = 1; attempt <= 3; attempt++) {
            System.out.println("=== Attempt " + attempt + " ===");

            ChatRequest withLines = new ChatRequest("qwen/qwen3.8-27b", messages, resformat, 0.0);

            String json = mapper.writeValueAsString(withLines);          // object -> JSON text

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.groq.com/openai/v1/chat/completions"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .timeout(Duration.ofMinutes(5))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response
                    = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println(response.statusCode());

            if (response.statusCode() != 200) {
                System.out.println(response.body());
                return;
            }

            JsonNode root = mapper.readTree(response.body());

            String word = root.get("choices").get(0).get("message")
                    .get("content").asString();

            System.out.println(word);

            TriageReport triage = mapper.readValue(word, TriageReport.class);
            if (triage.fixes() == null) {
                System.out.println("REJECTED: wrong shape");
                return;
            }
            Set<String> seen = new HashSet<>();
            List<String> problems = new ArrayList<>();
            Set<String> modelFix = new HashSet<>();
            for (PackageFix fix : triage.fixes()) {

                if (fix.packageName() == null) {
                    problems.add("REJECTED : empty entry");

                    continue;
                }

                seen.add(fix.packageName());

                for (String cve : fix.cves()) {
                    String pair = fix.packageName() + "|" + cve;
                    boolean returned = modelFix.add(pair);
                    if (!returned) {
                        problems.add("CONTRADICTION: " + pair);
                    }
                    if (fix.fixedVersion() != null && noFix.contains(pair)) {
                        problems.add("WRONG FIX: " + pair + " has no fix, but is listed under fixedVersion " + fix.fixedVersion());
                    }

                }

            }
            for (String pair : reportPairs) {
                if (!modelFix.contains(pair)) {
                    problems.add("FORGOTTEN :" + pair + "\n");

                }
            }

            for (String pair : modelFix) {
                if (!reportPairs.contains(pair)) {
                    problems.add("INVENTED : " + pair + "\n");

                }
            }

            System.out.println("Model pairs : " + modelFix.size());
            System.out.println("unique packages" + seen.size());

            if (problems.isEmpty()) {
                System.out.println("passed");
                break;
            } else {
                System.out.println("FAILED WITH :" + problems + " PROBLEMS");
                ChatMessage answerone = new ChatMessage("assistant", word);
                messages.add(answerone);
                ChatMessage missagetani = new ChatMessage("user", "Your answer has these problems: " + problems + ". Return the full corrected JSON with all packages and all CVEs.");
                messages.add(missagetani);

                System.out.println("Waiting 60s...");
                Thread.sleep(60_000);
                System.out.println("Done waiting");

            }
        }

    }

}
