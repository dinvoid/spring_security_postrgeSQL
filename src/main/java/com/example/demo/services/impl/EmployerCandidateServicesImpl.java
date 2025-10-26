package com.example.demo.services.impl;

import com.example.demo.dto.response.CandidateResponse;
import com.example.demo.dto.response.CandidateResponseSearchParam;
import com.example.demo.dto.response.CandidateSearchResponse;
import com.example.demo.models.Candidate;
import com.example.demo.repository.CandidateRepository;
import com.example.demo.services.EmployerCandidateServices;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EmployerCandidateServicesImpl implements EmployerCandidateServices {
    private final CandidateRepository candidateRepository;

    @Override
    public List<CandidateSearchResponse> getAllCandidateProfiles() {
        List<Object[]> results = candidateRepository.findAllCandidateProfiles();

        return results.stream()
                .map(r -> CandidateSearchResponse.builder()
                        .userId(((Number) r[0]).longValue())
                        .firstName((String) r[1])
                        .lastName((String) r[2])
                        .headline((String) r[3])
                        .summary((String) r[4])
                        .skills((String) r[5])
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public List<CandidateResponseSearchParam> searchCandidatesByParam(String skill, String headline) {
        return candidateRepository.searchCandidatesByParam(skill, headline);
    }



}