package com.example.demo.services.impl;

import com.example.demo.dto.response.CandidatePipelineResponse;
import com.example.demo.models.CandidatePipeline;
import com.example.demo.models.enumeration.PipelineStatus;
import com.example.demo.repository.CandidatePipelineRepository;
import com.example.demo.services.CandidatePipelineServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDate;

@Service
public class CandidatePipelineServicesImpl implements CandidatePipelineServices {
    @Autowired
    private CandidatePipelineRepository candidatePipelineRepository;
    public int getNextPosition(PipelineStatus status) {
        int maxPosition = candidatePipelineRepository.findMaxPositionByStatus(status);
        return maxPosition + 1; // next position
    }


    @Override
    public CandidatePipelineResponse addToKanban(@RequestParam Long emp, @RequestParam Long candidate) {
        PipelineStatus column = PipelineStatus.NEW; // example
        int position = getNextPosition(column);

        CandidatePipeline pipeline = CandidatePipeline.builder()
                .employerId(emp)
                .candidateId(candidate)
                .status(column)
                .position(position)
                .createdAt(LocalDate.now())
                .updatedAt(LocalDate.now())
                .build();

        CandidatePipeline saved = candidatePipelineRepository.save(pipeline);

        return CandidatePipelineResponse.builder()
                .id(saved.getId())
                .employer(emp)
                .candidate(saved.getCandidateId())
                .position(saved.getPosition())
                .status(column)
                .build();
    }

}
