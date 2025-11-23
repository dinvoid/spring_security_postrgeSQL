package com.example.demo.services;

import com.example.demo.dto.response.CandidatePipelineResponse;

import java.util.Map;

public interface CandidatePipelineServices {
    public CandidatePipelineResponse addToKanban(Long emp,Long candidate);
}
