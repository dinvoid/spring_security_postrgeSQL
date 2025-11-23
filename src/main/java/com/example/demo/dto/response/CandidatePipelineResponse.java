package com.example.demo.dto.response;

import com.example.demo.models.enumeration.PipelineStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CandidatePipelineResponse {
    private Long id;
    private Long employer;
    private Long candidate;
    private PipelineStatus status;
    private Integer position;
    private String notes;

}
