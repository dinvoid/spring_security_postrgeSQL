package com.example.demo.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CandidateRequest {
    private  Long id;
    private String firstName;
    private String lastName;
    private String headline;
    private String summary;
    private List<String> skills;
    private Long userId;
}
