package com.example.demo.dto.request;

import lombok.Data;
import java.util.List;

@Data
public class CandidateRequest {

    private String firstName;
    private String lastName;
    private String headline;
    private String summary;
    private List<String> skills;
    private Long userId;


}
