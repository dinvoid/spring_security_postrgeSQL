package com.example.demo.services;

import com.example.demo.dto.request.MoveCardRequest;
import com.example.demo.dto.response.CandidatePipelineResponse;

import java.util.List;
import java.util.Map;

public interface CandidatePipelineServices {
    public CandidatePipelineResponse addToKanban(Long emp,Long candidate);
    CandidatePipelineResponse moveCard(MoveCardRequest request);
    CandidatePipelineResponse moveCards(MoveCardRequest request);
    List<CandidatePipelineResponse> getAllCardsByEmployer(Long employerId);
}
