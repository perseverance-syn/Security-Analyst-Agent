package com.synch.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@JsonInclude(JsonInclude.Include.NON_NULL)
record AgentRequest(String model, List<ChatMessage> messages, JsonNode tools, double temperature) {}

public class AgentLoop {

    static ObjectMapper mapper = new ObjectMapper();
    static final String TOOLS_JSON = """
    [
      {
        "type": "function",
        "function": {
          "name": "get_cve_details",
          "description": "Get the affected packages, installed version, fixed version, severity and title for one CVE in the scanned image's report.",
          "parameters": {
            "type": "object",
            "properties": {
              "cve_id": { "type": "string", "description": "CVE identifier, e.g. CVE-2023-38545" }
            },
            "required": ["cve_id"]
          }
        }
      }
    ]
    """;

    static void main() throws Exception {
        ChatMessage userMessage = new ChatMessage("user", "What's the fix for CVE-2023-38545?");

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(userMessage);
        System.out.println(messages);

        JsonNode shape = mapper.readTree(TOOLS_JSON);

        AgentRequest request = new AgentRequest("qwen/qwen3.8-27b", messages, shape, 0.0);

        String json = mapper.writeValueAsString(request);
        System.out.println(json);

        HttpClient client = HttpClient.newHttpClient();

        String apiKey = System.getenv("GROQ_API_KEY");
        HttpRequest httprequest = HttpRequest.newBuilder()
                .uri(URI.create("https://api.groq.com/openai/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .timeout(Duration.ofMinutes(1))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpResponse<String> response
                = client.send(httprequest, HttpResponse.BodyHandlers.ofString());

        System.out.println(response.statusCode());

        if (response.statusCode() != 200) {
            System.out.println(response.body());
            return;
        } else {
            System.out.println(response.body());
        }

        JsonNode parsedbody = mapper.readTree(response.body());

        JsonNode reply = parsedbody.get("choices").get(0).get("message");
        JsonNode finishreason = parsedbody.get("choices").get(0).get("finish_reason");

        System.out.println(reply);
        System.out.print(finishreason.asString());

        String finishreasonstring = finishreason.asString();
        if (finishreasonstring.equals("tool_calls")) {
            ChatMessage assistantMessage = new ChatMessage("assistant", null, reply.get("tool_calls"), null);

            messages.add(assistantMessage);
            System.out.println(messages);
            JsonNode firstcall  = reply.get("tool_calls").get(0) ; 
            JsonNode callId = firstcall.get("id"); 
            String callIdString = callId.asString();
            System.out.println(callIdString);
            JsonNode arguments = firstcall.get("function").get("arguments") ; 
            String argumentsString = arguments.asString() ; 
            System.out.println(argumentsString);
        
            JsonNode argumentss = mapper.readTree(argumentsString) ; 
        
            JsonNode cveid = argumentss.get("cve_id") ; 
            String cveIDString = cveid.asString() ; 
          
            System.out.println(cveIDString);
          
          
          
          }   

    }

}
