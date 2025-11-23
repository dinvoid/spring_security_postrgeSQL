package com.example.demo.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CandidateResponse {
    @JsonIgnore
    private Long userId;
    private String firstName;
    private String lastName;
    private String headline;
    private String summary;
    private List<String> skills;
}
