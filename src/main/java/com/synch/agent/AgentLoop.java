package com.synch.agent;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@JsonInclude(JsonInclude.Include.NON_NULL)
record AgentRequest(String model, List<ChatMessage> messages, JsonNode tools, double temperature) {}

public class AgentLoop {
    static ObjectMapper mapper = new ObjectMapper() ; 
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

    static void main() {
        ChatMessage message = new ChatMessage("user", "What's the fix for CVE-2023-38545?");

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(message);
        System.out.println(messages);
    
        JsonNode shape = mapper.readTree(TOOLS_JSON);
    
    
        AgentRequest request = new AgentRequest("qwen/qwen3.8-27b",messages,shape,0.0) ; 
    
        String json = mapper.writeValueAsString(request);
        System.out.println(json);
    
    
    }








}
