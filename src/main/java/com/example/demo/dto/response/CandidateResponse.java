package com.example.demo.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CandidateResponse {
    private String firstName;
    private String lastName;
    private String headline;
    private String summary;
    private List<String> skills;
    private String education;
}
